/**
 * @file
 *
 * The committed known-answer file for comparison.
 *
 * The parser fails closed: a truncated case, a length that does not match the
 * hex, an odd nibble, an unknown expectation, or an uppercase hex digit is a
 * corrupt file, not a case to skip. Skipping would turn a broken corpus into
 * a green run.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include "test_helpers.h"

#include <cctype>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

namespace {

struct Case {
  std::string name;
  std::vector<unsigned char> a;
  std::vector<unsigned char> b;
  bool a_null = false;
  bool b_null = false;
  GSEC_Result expect = GSEC_ERR_INTERNAL;
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

bool parse_hex(const std::string & text, std::vector<unsigned char> * out,
    bool * is_null) {
  *is_null = false;
  out->clear();
  if (text == "-") {
    return true;
  }
  if (text == "null") {
    *is_null = true;
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

bool parse_expect(const std::string & text, GSEC_Result * out) {
  if (text == "ok") {
    *out = GSEC_OK;
    return true;
  }
  if (text == "mismatch") {
    *out = GSEC_ERR_MISMATCH;
    return true;
  }
  if (text == "invalid") {
    *out = GSEC_ERR_INVALID;
    return true;
  }
  return false;
}

/** Parse one file. Returns false and does not yield a partial success: either
 *  every case is well-formed or the file is rejected. */
bool parse_file(const std::string & text, std::vector<Case> * cases,
    std::string * error) {
  cases->clear();
  std::istringstream in(text);
  std::string line;
  bool saw_primitive = false;
  Case current;
  bool in_case = false;
  bool saw_len = false;
  bool saw_a = false;
  bool saw_b = false;
  bool saw_expect = false;
  size_t len = 0;
  int number = 0;

  auto finish = [&]() -> bool {
    if (!in_case) {
      return true;
    }
    if (!saw_len || !saw_a || !saw_b || !saw_expect || current.name.empty()) {
      *error = "truncated case " + current.name;
      return false;
    }
    if (!current.a_null && current.a.size() != len) {
      *error = "length does not match a in " + current.name;
      return false;
    }
    if (!current.b_null && current.b.size() != len) {
      *error = "length does not match b in " + current.name;
      return false;
    }
    if ((current.a_null || current.b_null) && len == 0) {
      *error = "null with length 0 in " + current.name;
      return false;
    }
    cases->push_back(current);
    in_case = false;
    return true;
  };

  while (std::getline(in, line)) {
    number++;
    if (!line.empty() && line.back() == '\r') {
      line.pop_back();
    }
    if (line.empty() || line[0] == '#') {
      continue;
    }
    std::istringstream row(line);
    std::string key;
    std::string value;
    row >> key >> value;
    std::string extra;
    if (key.empty() || value.empty() || (row >> extra)) {
      *error = "malformed line " + std::to_string(number);
      return false;
    }
    if (key == "primitive") {
      if (saw_primitive || value != "equal") {
        *error = "primitive line";
        return false;
      }
      saw_primitive = true;
      continue;
    }
    if (!saw_primitive) {
      *error = "case before primitive";
      return false;
    }
    if (key == "case") {
      if (!finish()) {
        return false;
      }
      current = Case();
      current.name = value;
      in_case = true;
      saw_len = saw_a = saw_b = saw_expect = false;
      len = 0;
      continue;
    }
    if (!in_case) {
      *error = "field outside a case";
      return false;
    }
    if (key == "len") {
      if (saw_len || value.empty()) {
        *error = "len";
        return false;
      }
      for (char c : value) {
        if (!std::isdigit(static_cast<unsigned char>(c))) {
          *error = "len is not decimal";
          return false;
        }
      }
      len = static_cast<size_t>(std::stoul(value));
      saw_len = true;
      continue;
    }
    if (key == "a" || key == "b") {
      std::vector<unsigned char> bytes;
      bool is_null = false;
      if (!parse_hex(value, &bytes, &is_null)) {
        *error = "hex in " + current.name;
        return false;
      }
      if (key == "a") {
        if (saw_a) {
          *error = "duplicate a";
          return false;
        }
        current.a = bytes;
        current.a_null = is_null;
        saw_a = true;
      } else {
        if (saw_b) {
          *error = "duplicate b";
          return false;
        }
        current.b = bytes;
        current.b_null = is_null;
        saw_b = true;
      }
      continue;
    }
    if (key == "expect") {
      if (saw_expect || !parse_expect(value, &current.expect)) {
        *error = "expect in " + current.name;
        return false;
      }
      saw_expect = true;
      continue;
    }
    *error = "unknown field " + key;
    return false;
  }
  if (!saw_primitive) {
    *error = "no primitive";
    return false;
  }
  if (!finish()) {
    return false;
  }
  if (cases->empty()) {
    *error = "no cases";
    return false;
  }
  return true;
}

std::string read_file(const std::string & path) {
  std::ifstream in(path);
  std::ostringstream buffer;
  buffer << in.rdbuf();
  return buffer.str();
}

} /* namespace */

TEST(Vectors, CommittedFileMatchesEveryCase) {
  std::string error;
  std::vector<Case> cases;
  std::string text = read_file(gsectest::data_dir() + "/vectors/equal.vec");
  ASSERT_FALSE(text.empty());
  ASSERT_TRUE(parse_file(text, &cases, &error)) << error;
  EXPECT_GE(cases.size(), 8u);
  for (const Case & item : cases) {
    const void * a = item.a_null ? nullptr : item.a.data();
    const void * b = item.b_null ? nullptr : item.b.data();
    size_t n = item.a_null ? item.b.size() : item.a.size();
    if (item.a_null && item.b_null) {
      n = 1;
    }
    EXPECT_EQ(gsec_equal(a, b, n), item.expect) << item.name;
  }
}

TEST(Vectors, TruncationAndBadHexAreRejected) {
  std::string error;
  std::vector<Case> cases;
  EXPECT_FALSE(parse_file("primitive equal\ncase only\nlen 1\n", &cases,
      &error));
  EXPECT_FALSE(parse_file(
      "primitive equal\ncase bad\nlen 1\na 0\nb 00\nexpect ok\n", &cases,
      &error));
  EXPECT_FALSE(parse_file(
      "primitive equal\ncase upper\nlen 1\na AA\nb AA\nexpect ok\n", &cases,
      &error));
  EXPECT_FALSE(parse_file(
      "primitive equal\ncase bool\nlen 1\na 00\nb 00\nexpect true\n", &cases,
      &error));
  EXPECT_FALSE(parse_file(
      "primitive equal\ncase short\nlen 2\na 00\nb 0000\nexpect ok\n", &cases,
      &error));
  EXPECT_TRUE(cases.empty());
}

TEST(Vectors, APrefixOfTheTagIsNotSuccess) {
  /* The historical HMAC failure: stop at the first differing byte, or accept
   * a truncated tag. The file format has no "prefix" expectation, and a
   * one-byte tag against a two-byte tag is a length error in the file, which
   * is rejected rather than compared. */
  std::string error;
  std::vector<Case> cases;
  EXPECT_FALSE(parse_file(
      "primitive equal\ncase trunc\nlen 2\na 0000\nb 00\nexpect ok\n", &cases,
      &error));
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
