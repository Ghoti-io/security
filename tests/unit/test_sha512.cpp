/**
 * @file
 *
 * SHA-512 and SHA-384 against the committed files, and the contract around
 * them.
 *
 * SHA-384 is the same compression with a different initial value. The
 * digests in the files are RFC 6234 plus the lengths that change where the
 * padding block falls. `make check-oracle` is the comparison with OpenSSL.
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

bool parse_file(const std::string & text, const char * primitive,
    size_t digest_len, std::vector<Case> * cases, std::string * error) {
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
    if (current.digest.size() != digest_len) {
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
      if (saw_primitive || value != primitive) {
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

std::string load_file(const char * name) {
  std::ifstream in(std::string(GSEC_TEST_DATA) + "/vectors/" + name);
  std::ostringstream buf;
  buf << in.rdbuf();
  return buf.str();
}

template <typename Ctx>
struct Alg;

template <>
struct Alg<GSEC_Sha512> {
  static constexpr size_t digest_len = GSEC_SHA512_DIGEST_LEN;
  static constexpr uint32_t magic = 0x53484135u;
  static constexpr const char * primitive = "sha512";
  static constexpr const char * file = "sha512.vec";
  static GSEC_Result oneshot(const void * data, size_t n, unsigned char * out) {
    return gsec_sha512(data, n, out);
  }
  static GSEC_Result init(GSEC_Sha512 * ctx) { return gsec_sha512_init(ctx); }
  static GSEC_Result update(GSEC_Sha512 * ctx, const void * data, size_t n) {
    return gsec_sha512_update(ctx, data, n);
  }
  static GSEC_Result final(GSEC_Sha512 * ctx, unsigned char * out) {
    return gsec_sha512_final(ctx, out);
  }
};

template <>
struct Alg<GSEC_Sha384> {
  static constexpr size_t digest_len = GSEC_SHA384_DIGEST_LEN;
  static constexpr uint32_t magic = 0x53483338u;
  static constexpr const char * primitive = "sha384";
  static constexpr const char * file = "sha384.vec";
  static GSEC_Result oneshot(const void * data, size_t n, unsigned char * out) {
    return gsec_sha384(data, n, out);
  }
  static GSEC_Result init(GSEC_Sha384 * ctx) { return gsec_sha384_init(ctx); }
  static GSEC_Result update(GSEC_Sha384 * ctx, const void * data, size_t n) {
    return gsec_sha384_update(ctx, data, n);
  }
  static GSEC_Result final(GSEC_Sha384 * ctx, unsigned char * out) {
    return gsec_sha384_final(ctx, out);
  }
};

template <typename Ctx>
void expect_hash(const unsigned char * msg, size_t n,
    const unsigned char * digest) {
  unsigned char got[Alg<Ctx>::digest_len];
  unsigned char streamed[Alg<Ctx>::digest_len];
  Ctx ctx;
  size_t i;

  ASSERT_EQ(Alg<Ctx>::oneshot(n == 0 ? nullptr : msg, n, got), GSEC_OK);
  EXPECT_EQ(gsec_equal(got, digest, Alg<Ctx>::digest_len), GSEC_OK);

  ASSERT_EQ(Alg<Ctx>::init(&ctx), GSEC_OK);
  for (i = 0; i < n; i++) {
    ASSERT_EQ(Alg<Ctx>::update(&ctx, msg + i, 1), GSEC_OK);
  }
  ASSERT_EQ(Alg<Ctx>::final(&ctx, streamed), GSEC_OK);
  EXPECT_EQ(gsec_equal(got, streamed, Alg<Ctx>::digest_len), GSEC_OK);
  EXPECT_EQ(gsec_wipe(got, sizeof got), GSEC_OK);
  EXPECT_EQ(gsec_wipe(streamed, sizeof streamed), GSEC_OK);
}

template <typename Ctx>
void committed_file() {
  std::string error;
  std::vector<Case> cases;
  ASSERT_TRUE(parse_file(load_file(Alg<Ctx>::file), Alg<Ctx>::primitive,
      Alg<Ctx>::digest_len, &cases, &error)) << error;
  ASSERT_GE(cases.size(), 3u);
  for (const Case & item : cases) {
    SCOPED_TRACE(item.name);
    expect_hash<Ctx>(item.msg.empty() ? nullptr : item.msg.data(),
        item.msg.size(), item.digest.data());
  }
}

template <typename Ctx>
void arguments() {
  Ctx ctx;
  unsigned char dig[Alg<Ctx>::digest_len];
  unsigned char zeros[sizeof ctx];
  const unsigned char byte = 0x61;

  EXPECT_EQ(Alg<Ctx>::init(nullptr), GSEC_ERR_INVALID);
  EXPECT_EQ(Alg<Ctx>::oneshot(nullptr, 1, dig), GSEC_ERR_INVALID);
  EXPECT_EQ(Alg<Ctx>::oneshot(&byte, 1, nullptr), GSEC_ERR_INVALID);

  ASSERT_EQ(Alg<Ctx>::init(&ctx), GSEC_OK);
  EXPECT_EQ(Alg<Ctx>::update(nullptr, &byte, 1), GSEC_ERR_INVALID);
  EXPECT_EQ(Alg<Ctx>::update(&ctx, nullptr, 1), GSEC_ERR_INVALID);
  EXPECT_EQ(Alg<Ctx>::update(&ctx, nullptr, 0), GSEC_OK);
  EXPECT_EQ(Alg<Ctx>::final(&ctx, nullptr), GSEC_ERR_INVALID);
  EXPECT_EQ(ctx.magic, Alg<Ctx>::magic);
  ASSERT_EQ(Alg<Ctx>::final(&ctx, dig), GSEC_OK);
  std::memset(zeros, 0, sizeof zeros);
  EXPECT_EQ(gsec_equal(reinterpret_cast<unsigned char *>(&ctx), zeros,
      sizeof ctx), GSEC_OK);
  EXPECT_EQ(Alg<Ctx>::update(&ctx, &byte, 1), GSEC_ERR_INVALID);
  EXPECT_EQ(Alg<Ctx>::final(&ctx, dig), GSEC_ERR_INVALID);
  EXPECT_EQ(gsec_wipe(dig, sizeof dig), GSEC_OK);
}

template <typename Ctx>
void million(const unsigned char * digest) {
  std::vector<unsigned char> msg(1000000, static_cast<unsigned char>('a'));
  unsigned char got[Alg<Ctx>::digest_len];
  Ctx ctx;
  size_t off;

  ASSERT_EQ(Alg<Ctx>::oneshot(msg.data(), msg.size(), got), GSEC_OK);
  EXPECT_EQ(gsec_equal(got, digest, Alg<Ctx>::digest_len), GSEC_OK);

  ASSERT_EQ(Alg<Ctx>::init(&ctx), GSEC_OK);
  for (off = 0; off < msg.size(); off += 1000) {
    ASSERT_EQ(Alg<Ctx>::update(&ctx, msg.data() + off, 1000), GSEC_OK);
  }
  ASSERT_EQ(Alg<Ctx>::final(&ctx, got), GSEC_OK);
  EXPECT_EQ(gsec_equal(got, digest, Alg<Ctx>::digest_len), GSEC_OK);
  EXPECT_EQ(gsec_wipe(got, sizeof got), GSEC_OK);
}

}  /* namespace */

TEST(Sha512, CommittedFileMatchesEveryCase) {
  committed_file<GSEC_Sha512>();
}

TEST(Sha384, CommittedFileMatchesEveryCase) {
  committed_file<GSEC_Sha384>();
}

TEST(Sha512, ABadFileIsNotASkippedCase) {
  std::string error;
  std::vector<Case> cases;
  EXPECT_FALSE(parse_file("case bare\nmsg -\ndigest ab\n", "sha512",
      GSEC_SHA512_DIGEST_LEN, &cases, &error));
  EXPECT_FALSE(parse_file("primitive sha512\ncase short\nmsg 61\ndigest aa\n",
      "sha512", GSEC_SHA512_DIGEST_LEN, &cases, &error));
  EXPECT_TRUE(cases.empty());
}

TEST(Sha512, MillionAsMatchRfc6234) {
  static const unsigned char digest[GSEC_SHA512_DIGEST_LEN] = {
    0xe7, 0x18, 0x48, 0x3d, 0x0c, 0xe7, 0x69, 0x64,
    0x4e, 0x2e, 0x42, 0xc7, 0xbc, 0x15, 0xb4, 0x63,
    0x8e, 0x1f, 0x98, 0xb1, 0x3b, 0x20, 0x44, 0x28,
    0x56, 0x32, 0xa8, 0x03, 0xaf, 0xa9, 0x73, 0xeb,
    0xde, 0x0f, 0xf2, 0x44, 0x87, 0x7e, 0xa6, 0x0a,
    0x4c, 0xb0, 0x43, 0x2c, 0xe5, 0x77, 0xc3, 0x1b,
    0xeb, 0x00, 0x9c, 0x5c, 0x2c, 0x49, 0xaa, 0x2e,
    0x4e, 0xad, 0xb2, 0x17, 0xad, 0x8c, 0xc0, 0x9b
  };
  million<GSEC_Sha512>(digest);
}

TEST(Sha384, MillionAsMatchRfc6234) {
  static const unsigned char digest[GSEC_SHA384_DIGEST_LEN] = {
    0x9d, 0x0e, 0x18, 0x09, 0x71, 0x64, 0x74, 0xcb,
    0x08, 0x6e, 0x83, 0x4e, 0x31, 0x0a, 0x4a, 0x1c,
    0xed, 0x14, 0x9e, 0x9c, 0x00, 0xf2, 0x48, 0x52,
    0x79, 0x72, 0xce, 0xc5, 0x70, 0x4c, 0x2a, 0x5b,
    0x07, 0xb8, 0xb3, 0xdc, 0x38, 0xec, 0xc4, 0xeb,
    0xae, 0x97, 0xdd, 0xd8, 0x7f, 0x3d, 0x89, 0x85
  };
  million<GSEC_Sha384>(digest);
}

TEST(Sha512, ArgumentsAndAFinishedContext) {
  arguments<GSEC_Sha512>();
}

TEST(Sha384, ArgumentsAndAFinishedContext) {
  arguments<GSEC_Sha384>();
}

TEST(Sha384, IsNotATruncationOfSha512) {
  static const unsigned char msg[3] = {0x61, 0x62, 0x63};
  unsigned char wide[GSEC_SHA512_DIGEST_LEN];
  unsigned char narrow[GSEC_SHA384_DIGEST_LEN];

  ASSERT_EQ(gsec_sha512(msg, sizeof msg, wide), GSEC_OK);
  ASSERT_EQ(gsec_sha384(msg, sizeof msg, narrow), GSEC_OK);
  EXPECT_EQ(gsec_equal(wide, narrow, GSEC_SHA384_DIGEST_LEN), GSEC_ERR_MISMATCH);
  EXPECT_EQ(gsec_wipe(wide, sizeof wide), GSEC_OK);
  EXPECT_EQ(gsec_wipe(narrow, sizeof narrow), GSEC_OK);
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
