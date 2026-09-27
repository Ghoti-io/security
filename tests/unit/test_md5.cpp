/**
 * @file
 *
 * MD5 against the committed file, and the contract around it.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include "test_helpers.h"

#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

namespace {

struct Case {
  std::string name;
  std::vector<unsigned char> msg;
  std::vector<unsigned char> digest;
};

int hex_value(char c) {
  if (c >= '0' && c <= '9') {
    return c - '0';
  }
  if (c >= 'a' && c <= 'f') {
    return c - 'a' + 10;
  }
  return -1;
}

bool parse_hex(const std::string & text, std::vector<unsigned char> * out) {
  out->clear();
  if (text == "-") {
    return true;
  }
  if (text.size() % 2 != 0) {
    return false;
  }
  for (size_t i = 0; i < text.size(); i += 2) {
    int hi = hex_value(text[i]);
    int lo = hex_value(text[i + 1]);
    if (hi < 0 || lo < 0) {
      return false;
    }
    out->push_back(static_cast<unsigned char>((hi << 4) | lo));
  }
  return true;
}

bool parse_file(const std::string & text, std::vector<Case> * cases,
    std::string * error) {
  cases->clear();
  std::istringstream in(text);
  std::string line;
  bool saw_primitive = false;
  Case current;
  bool in_case = false;
  bool saw_msg = false;
  bool saw_digest = false;

  auto finish = [&]() -> bool {
    if (!in_case) {
      return true;
    }
    if (current.name.empty() || !saw_msg || !saw_digest) {
      *error = "truncated case " + current.name;
      return false;
    }
    if (current.digest.size() != GSEC_MD5_DIGEST_LEN) {
      *error = "digest length in " + current.name;
      return false;
    }
    cases->push_back(current);
    return true;
  };

  while (std::getline(in, line)) {
    if (!line.empty() && line.back() == '\r') {
      line.pop_back();
    }
    if (line.empty() || line[0] == '#') {
      continue;
    }
    std::istringstream row(line);
    std::string key;
    std::string value;
    row >> key;
    std::getline(row, value);
    if (!value.empty() && value[0] == ' ') {
      value.erase(0, 1);
    }
    if (key == "primitive") {
      if (saw_primitive || value != "md5") {
        *error = "primitive";
        return false;
      }
      saw_primitive = true;
      continue;
    }
    if (!saw_primitive) {
      *error = "primitive missing";
      return false;
    }
    if (key == "case") {
      if (!finish()) {
        return false;
      }
      current = Case();
      current.name = value;
      in_case = true;
      saw_msg = false;
      saw_digest = false;
      continue;
    }
    if (!in_case || value.empty()) {
      *error = "orphan field";
      return false;
    }
    if (key == "msg") {
      if (saw_msg || !parse_hex(value, &current.msg)) {
        *error = "msg in " + current.name;
        return false;
      }
      saw_msg = true;
      continue;
    }
    if (key == "digest") {
      if (saw_digest || !parse_hex(value, &current.digest)) {
        *error = "digest in " + current.name;
        return false;
      }
      saw_digest = true;
      continue;
    }
    *error = "unknown field";
    return false;
  }
  if (!saw_primitive) {
    *error = "primitive missing";
    return false;
  }
  return finish();
}

std::string load_committed() {
  std::ifstream in(std::string(GSEC_TEST_DATA) + "/vectors/md5.vec");
  std::ostringstream buf;
  buf << in.rdbuf();
  return buf.str();
}

void expect_hash(const unsigned char * msg, size_t n,
    const unsigned char * digest) {
  unsigned char got[GSEC_MD5_DIGEST_LEN];
  unsigned char streamed[GSEC_MD5_DIGEST_LEN];
  GSEC_Md5 ctx;
  size_t i;

  ASSERT_EQ(gsec_md5(n == 0 ? nullptr : msg, n, got), GSEC_OK);
  EXPECT_EQ(gsec_equal(got, digest, GSEC_MD5_DIGEST_LEN), GSEC_OK);

  ASSERT_EQ(gsec_md5_init(&ctx), GSEC_OK);
  for (i = 0; i < n; i++) {
    ASSERT_EQ(gsec_md5_update(&ctx, msg + i, 1), GSEC_OK);
  }
  ASSERT_EQ(gsec_md5_final(&ctx, streamed), GSEC_OK);
  EXPECT_EQ(gsec_equal(got, streamed, GSEC_MD5_DIGEST_LEN), GSEC_OK);
  EXPECT_EQ(gsec_wipe(got, sizeof got), GSEC_OK);
  EXPECT_EQ(gsec_wipe(streamed, sizeof streamed), GSEC_OK);
}

}  /* namespace */

TEST(Md5, CommittedFileMatchesEveryCase) {
  std::string error;
  std::vector<Case> cases;
  ASSERT_TRUE(parse_file(load_committed(), &cases, &error)) << error;
  ASSERT_GE(cases.size(), 3u);
  for (const Case & item : cases) {
    SCOPED_TRACE(item.name);
    expect_hash(item.msg.empty() ? nullptr : item.msg.data(), item.msg.size(),
        item.digest.data());
  }
}

TEST(Md5, ABadFileIsNotASkippedCase) {
  std::string error;
  std::vector<Case> cases;
  EXPECT_FALSE(parse_file("primitive md5\ncase short\nmsg 61\ndigest aa\n",
      &cases, &error));
  EXPECT_TRUE(cases.empty());
}

TEST(Md5, MillionAsMatchThePublishedDigest) {
  static const unsigned char digest[GSEC_MD5_DIGEST_LEN] = {
    0x77, 0x07, 0xd6, 0xae, 0x4e, 0x02, 0x7c, 0x70,
    0xee, 0xa2, 0xa9, 0x35, 0xc2, 0x29, 0x6f, 0x21
  };
  std::vector<unsigned char> msg(1000000, static_cast<unsigned char>('a'));
  unsigned char got[GSEC_MD5_DIGEST_LEN];
  GSEC_Md5 ctx;
  size_t off;

  ASSERT_EQ(gsec_md5(msg.data(), msg.size(), got), GSEC_OK);
  EXPECT_EQ(gsec_equal(got, digest, sizeof got), GSEC_OK);

  ASSERT_EQ(gsec_md5_init(&ctx), GSEC_OK);
  for (off = 0; off < msg.size(); off += 1000) {
    ASSERT_EQ(gsec_md5_update(&ctx, msg.data() + off, 1000), GSEC_OK);
  }
  ASSERT_EQ(gsec_md5_final(&ctx, got), GSEC_OK);
  EXPECT_EQ(gsec_equal(got, digest, sizeof got), GSEC_OK);
  EXPECT_EQ(gsec_wipe(got, sizeof got), GSEC_OK);
}

TEST(Md5, ArgumentsAndAFinishedContext) {
  GSEC_Md5 ctx;
  unsigned char dig[GSEC_MD5_DIGEST_LEN];
  unsigned char zeros[sizeof ctx];
  const unsigned char byte = 0x61;

  EXPECT_EQ(gsec_md5_init(nullptr), GSEC_ERR_INVALID);
  EXPECT_EQ(gsec_md5(nullptr, 1, dig), GSEC_ERR_INVALID);
  EXPECT_EQ(gsec_md5(&byte, 1, nullptr), GSEC_ERR_INVALID);

  ASSERT_EQ(gsec_md5_init(&ctx), GSEC_OK);
  EXPECT_EQ(gsec_md5_update(nullptr, &byte, 1), GSEC_ERR_INVALID);
  EXPECT_EQ(gsec_md5_update(&ctx, nullptr, 1), GSEC_ERR_INVALID);
  EXPECT_EQ(gsec_md5_update(&ctx, nullptr, 0), GSEC_OK);
  EXPECT_EQ(gsec_md5_final(&ctx, nullptr), GSEC_ERR_INVALID);
  EXPECT_EQ(ctx.magic, 0x4d443501u);
  ASSERT_EQ(gsec_md5_final(&ctx, dig), GSEC_OK);
  std::memset(zeros, 0, sizeof zeros);
  EXPECT_EQ(gsec_equal(reinterpret_cast<unsigned char *>(&ctx), zeros,
      sizeof ctx), GSEC_OK);
  EXPECT_EQ(gsec_md5_update(&ctx, &byte, 1), GSEC_ERR_INVALID);
  EXPECT_EQ(gsec_md5_final(&ctx, dig), GSEC_ERR_INVALID);
  EXPECT_EQ(gsec_wipe(dig, sizeof dig), GSEC_OK);
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
