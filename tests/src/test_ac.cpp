/**
 * @file test_ac.cpp
 * @brief Unit tests for the Aho-Corasick module and V4 two-stage pipeline.
 */

#include <gtest/gtest.h>
#include <cstring>
#include <cstdlib>
#include <algorithm>
#include <vector>

extern "C" {
#include "zdpi_types.h"
#include "rule_parser.h"
#include "regex_parser.h"
#include "nfa.h"
#include "dfa.h"
#include "mfsa.h"
#include "ac.h"
#include "ec_compress.h"
#include "linearize.h"
}

/* ---- Aho-Corasick unit tests ---- */

class AcTest : public ::testing::Test {
protected:
	void TearDown() override
	{
		dfa_free(&dfa_);
		ac_match_info_free(&mi_);
	}

	int build(const std::vector<std::pair<std::string, uint32_t>> &pats)
	{
		std::vector<struct ac_pattern> ac_pats;
		for (auto &p : pats) {
			struct ac_pattern ap;
			ap.data = (const uint8_t *)p.first.c_str();
			ap.len = (uint32_t)p.first.size();
			ap.pattern_id = p.second;
			ac_pats.push_back(ap);
		}
		memset(&dfa_, 0, sizeof(dfa_));
		memset(&mi_, 0, sizeof(mi_));
		return ac_build(ac_pats.data(),
				(uint32_t)ac_pats.size(),
				&dfa_, &mi_);
	}

	/* Simulate AC DFA on input, return set of matched pattern IDs */
	std::vector<uint32_t> simulate(const char *input)
	{
		std::vector<uint32_t> result;
		uint32_t state = ZDPI_START_STATE;
		uint32_t len = (uint32_t)strlen(input);
		for (uint32_t i = 0; i < len; i++) {
			uint8_t byte = (uint8_t)input[i];
			if (state >= dfa_.num_states)
				break;
			state = dfa_.states[state].trans[byte];
			if (state == ZDPI_DEAD_STATE)
				break;
			if (state < mi_.num_states &&
			    mi_.state_counts[state] > 0) {
				uint32_t off = mi_.state_offsets[state];
				uint32_t cnt = mi_.state_counts[state];
				for (uint32_t j = 0; j < cnt; j++)
					result.push_back(
						mi_.pattern_ids[off + j]);
			}
		}
		/* Sort and deduplicate */
		std::sort(result.begin(), result.end());
		result.erase(std::unique(result.begin(), result.end()),
			     result.end());
		return result;
	}

	bool has_match(const char *input, uint32_t pattern_id)
	{
		auto matches = simulate(input);
		return std::find(matches.begin(), matches.end(),
				 pattern_id) != matches.end();
	}

	struct dfa dfa_ = {};
	struct ac_match_info mi_ = {};
};

TEST_F(AcTest, ClassicACExample)
{
	/* Classic example: {"he","she","his","hers"} */
	ASSERT_EQ(build({{"he", 0}, {"she", 1}, {"his", 2}, {"hers", 3}}),
		  ZDPI_OK);
	EXPECT_TRUE(has_match("she", 1));
	EXPECT_TRUE(has_match("she", 0));	/* "he" is suffix of "she" */
	EXPECT_TRUE(has_match("his", 2));
	EXPECT_TRUE(has_match("hers", 3));
	EXPECT_TRUE(has_match("hers", 0));	/* "he" prefix */
	EXPECT_TRUE(has_match("ushers", 0));
	EXPECT_TRUE(has_match("ushers", 1));
	EXPECT_TRUE(has_match("ushers", 3));
}

TEST_F(AcTest, SinglePattern)
{
	ASSERT_EQ(build({{"abc", 42}}), ZDPI_OK);
	EXPECT_TRUE(has_match("abc", 42));
	EXPECT_TRUE(has_match("xabcy", 42));
	EXPECT_FALSE(has_match("ab", 42));
	EXPECT_FALSE(has_match("xyz", 42));
}

TEST_F(AcTest, OverlappingPatterns)
{
	ASSERT_EQ(build({{"abc", 0}, {"bc", 1}}), ZDPI_OK);
	auto m = simulate("abc");
	EXPECT_EQ(m.size(), 2u);
	EXPECT_TRUE(has_match("abc", 0));
	EXPECT_TRUE(has_match("abc", 1));
	/* "bc" alone */
	EXPECT_TRUE(has_match("xbcy", 1));
	EXPECT_FALSE(has_match("xbcy", 0));
}

TEST_F(AcTest, SingleCharPatterns)
{
	ASSERT_EQ(build({{"a", 0}, {"b", 1}, {"c", 2}}), ZDPI_OK);
	EXPECT_TRUE(has_match("a", 0));
	EXPECT_TRUE(has_match("b", 1));
	EXPECT_TRUE(has_match("abc", 0));
	EXPECT_TRUE(has_match("abc", 1));
	EXPECT_TRUE(has_match("abc", 2));
	EXPECT_FALSE(has_match("xyz", 0));
}

TEST_F(AcTest, HexContentBytes)
{
	/* Pattern with non-printable bytes */
	std::string pat("\x2E\x2F", 2); /* "./" */
	ASSERT_EQ(build({{pat, 0}}), ZDPI_OK);
	EXPECT_TRUE(has_match("./", 0));
	EXPECT_TRUE(has_match("x./y", 0));
	EXPECT_FALSE(has_match("xy", 0));
}

TEST_F(AcTest, MatchInfoCorrectness)
{
	ASSERT_EQ(build({{"ab", 10}, {"b", 20}}), ZDPI_OK);
	/* Verify match_info has correct structure */
	EXPECT_EQ(mi_.num_states, dfa_.num_states);
	EXPECT_GE(mi_.total_matches, 2u);

	/* At least one state should have 2 matches (accept for "ab"
	 * also gets "b" via suffix) */
	bool found_multi = false;
	for (uint32_t s = 0; s < mi_.num_states; s++) {
		if (mi_.state_counts[s] >= 2)
			found_multi = true;
	}
	EXPECT_TRUE(found_multi);
}

TEST_F(AcTest, LargePatternCount)
{
	std::vector<std::pair<std::string, uint32_t>> pats;
	for (uint32_t i = 0; i < 500; i++) {
		char buf[16];
		snprintf(buf, sizeof(buf), "pat%04u", i);
		pats.push_back({buf, i});
	}
	ASSERT_EQ(build(pats), ZDPI_OK);
	EXPECT_TRUE(has_match("pat0000", 0));
	EXPECT_TRUE(has_match("pat0499", 499));
	EXPECT_TRUE(has_match("xxxpat0250yyy", 250));
}

TEST_F(AcTest, EmptyPatternSetFails)
{
	std::vector<struct ac_pattern> empty;
	memset(&dfa_, 0, sizeof(dfa_));
	memset(&mi_, 0, sizeof(mi_));
	int rc = ac_build(empty.data(), 0, &dfa_, &mi_);
	EXPECT_NE(rc, ZDPI_OK);
}

TEST_F(AcTest, NoMatchOnUnrelatedInput)
{
	ASSERT_EQ(build({{"hello", 0}, {"world", 1}}), ZDPI_OK);
	auto m = simulate("zzzzz");
	EXPECT_TRUE(m.empty());
}

/* ---- Content parser tests ---- */

class ContentParserTest : public ::testing::Test {
};

TEST_F(ContentParserTest, BasicTextContent)
{
	struct zdpi_rule rule;
	const char *line = "alert tcp any any -> any 80 "
		"(content:\"SELECT\"; pcre:\"/SELECT/\"; sid:100;)";
	int rc = rule_parse_line(line, &rule);
	ASSERT_EQ(rc, ZDPI_OK);
	EXPECT_EQ(rule.num_contents, 1u);
	EXPECT_EQ(rule.contents[0].len, 6u);
	EXPECT_EQ(memcmp(rule.contents[0].data, "SELECT", 6), 0);
	EXPECT_FALSE(rule.contents[0].nocase);
	EXPECT_FALSE(rule.contents[0].negated);
}

TEST_F(ContentParserTest, HexContent)
{
	struct zdpi_rule rule;
	const char *line = "alert tcp any any -> any 80 "
		"(content:\"|2E 2F|\"; pcre:\"/\\x2e\\x2f/\"; sid:101;)";
	int rc = rule_parse_line(line, &rule);
	ASSERT_EQ(rc, ZDPI_OK);
	EXPECT_EQ(rule.num_contents, 1u);
	EXPECT_EQ(rule.contents[0].len, 2u);
	EXPECT_EQ(rule.contents[0].data[0], 0x2E);
	EXPECT_EQ(rule.contents[0].data[1], 0x2F);
}

TEST_F(ContentParserTest, NocaseContent)
{
	struct zdpi_rule rule;
	const char *line = "alert tcp any any -> any 80 "
		"(content:\"SELECT\"; nocase; pcre:\"/SELECT/\"; sid:102;)";
	int rc = rule_parse_line(line, &rule);
	ASSERT_EQ(rc, ZDPI_OK);
	EXPECT_EQ(rule.num_contents, 1u);
	EXPECT_TRUE(rule.contents[0].nocase);
	/* Data should be lowercased */
	EXPECT_EQ(memcmp(rule.contents[0].data, "select", 6), 0);
}

TEST_F(ContentParserTest, NegatedContent)
{
	struct zdpi_rule rule;
	const char *line = "alert tcp any any -> any 80 "
		"(content:!\"negative\"; pcre:\"/test/\"; sid:103;)";
	int rc = rule_parse_line(line, &rule);
	ASSERT_EQ(rc, ZDPI_OK);
	EXPECT_EQ(rule.num_contents, 1u);
	EXPECT_TRUE(rule.contents[0].negated);
}

TEST_F(ContentParserTest, MultipleContents)
{
	struct zdpi_rule rule;
	const char *line = "alert tcp any any -> any 80 "
		"(content:\"abc\"; content:\"xyz\"; "
		"pcre:\"/test/\"; sid:104;)";
	int rc = rule_parse_line(line, &rule);
	ASSERT_EQ(rc, ZDPI_OK);
	EXPECT_EQ(rule.num_contents, 2u);
	EXPECT_EQ(rule.contents[0].len, 3u);
	EXPECT_EQ(rule.contents[1].len, 3u);
}

TEST_F(ContentParserTest, NoContentField)
{
	struct zdpi_rule rule;
	const char *line = "alert tcp any any -> any 80 "
		"(pcre:\"/test/\"; sid:105;)";
	int rc = rule_parse_line(line, &rule);
	ASSERT_EQ(rc, ZDPI_OK);
	EXPECT_EQ(rule.num_contents, 0u);
}

/* ---- V4 E2E tests ---- */

class V4E2eTest : public ::testing::Test {
protected:
	void SetUp() override
	{
		memset(&blob_, 0, sizeof(blob_));
	}

	void TearDown() override
	{
		arena_blob_free(&blob_);
	}

	/**
	 * Build a V4 blob from content keywords + pcre patterns.
	 * Each element: {content_keyword, pcre_pattern}
	 * If content is empty, the rule is "always-run".
	 */
	int build_v4(
		const std::vector<std::pair<std::string, std::string>> &rules)
	{
		uint32_t count = (uint32_t)rules.size();

		/* Build MFSA DFAs from PCRE patterns */
		std::vector<struct re_token_stream> streams(count);
		std::vector<uint32_t> rule_ids(count);
		for (uint32_t i = 0; i < count; i++) {
			int rc = regex_parse(rules[i].second.c_str(),
					     &streams[i]);
			if (rc)
				return rc;
			rule_ids[i] = i + 1;
		}

		struct mfsa mfsa_g;
		int rc = mfsa_build(streams.data(), count,
				    rule_ids.data(), &mfsa_g);
		if (rc)
			return rc;

		/* Unanchor MFSA DFAs */
		for (uint32_t di = 0; di < mfsa_g.num_dfas; di++) {
			struct dfa *d = &mfsa_g.dfas[di];
			for (int c = 0; c < ZDPI_ALPHABET_SIZE; c++) {
				if (d->states[ZDPI_START_STATE].trans[c]
				    == ZDPI_DEAD_STATE)
					d->states[ZDPI_START_STATE]
						.trans[c] =
						ZDPI_START_STATE;
			}
			for (uint32_t s = 2; s < d->num_states; s++) {
				for (int c = 0;
				     c < ZDPI_ALPHABET_SIZE; c++) {
					if (d->states[s].trans[c] ==
					    ZDPI_DEAD_STATE)
						d->states[s].trans[c] =
							d->states
							[ZDPI_START_STATE]
								.trans[c];
				}
			}
		}

		/* Build AC patterns from content keywords.
		 * Collect strings first, then set pointers push_back
		 * can reallocate and invalidate earlier c_str() ptrs. */
		std::vector<uint16_t> always_run;
		std::vector<std::string> content_strs;
		std::vector<uint32_t> content_indices;

		for (uint32_t i = 0; i < count; i++) {
			if (rules[i].first.empty()) {
				always_run.push_back((uint16_t)i);
			} else {
				content_strs.push_back(rules[i].first);
				content_indices.push_back(i);
			}
		}

		/* Now build ac_pats with stable pointers */
		std::vector<struct ac_pattern> ac_pats(
			content_strs.size());
		for (size_t j = 0; j < content_strs.size(); j++) {
			ac_pats[j].data = (const uint8_t *)
				content_strs[j].c_str();
			ac_pats[j].len = (uint32_t)
				content_strs[j].size();
			ac_pats[j].pattern_id = content_indices[j];
		}

		struct dfa ac_dfa;
		struct ac_match_info match_info;
		if (!ac_pats.empty()) {
			rc = ac_build(ac_pats.data(),
				      (uint32_t)ac_pats.size(),
				      &ac_dfa, &match_info);
		} else {
			rc = dfa_alloc(&ac_dfa, 2);
			if (!rc) {
				ac_dfa.num_states = 2;
				memset(&match_info, 0,
				       sizeof(match_info));
				match_info.num_states = 2;
				match_info.state_offsets =
					(uint32_t *)calloc(
						2, sizeof(uint32_t));
				match_info.state_counts =
					(uint32_t *)calloc(
						2, sizeof(uint32_t));
			}
		}
		if (rc) {
			mfsa_free(&mfsa_g);
			return rc;
		}

		/* EC compress AC */
		struct ec_map ac_ecm;
		rc = ec_compute(&ac_dfa, &ac_ecm);
		if (rc) {
			dfa_free(&ac_dfa);
			ac_match_info_free(&match_info);
			mfsa_free(&mfsa_g);
			return rc;
		}

		struct ec_table ac_ect;
		rc = ec_table_build(&ac_dfa, &ac_ecm, &ac_ect);
		dfa_free(&ac_dfa);
		if (rc) {
			ac_match_info_free(&match_info);
			mfsa_free(&mfsa_g);
			return rc;
		}

		/* EC compress MFSA DFAs */
		std::vector<const struct dfa *> dfa_ptrs(mfsa_g.num_dfas);
		for (uint32_t i = 0; i < mfsa_g.num_dfas; i++)
			dfa_ptrs[i] = &mfsa_g.dfas[i];

		struct ec_map mfsa_ecm;
		rc = ec_compute_multi(dfa_ptrs.data(),
				      mfsa_g.num_dfas, &mfsa_ecm);
		if (rc) {
			ec_table_free(&ac_ect);
			ac_match_info_free(&match_info);
			mfsa_free(&mfsa_g);
			return rc;
		}

		std::vector<struct ec_table> mfsa_ects(mfsa_g.num_dfas);
		for (uint32_t i = 0; i < mfsa_g.num_dfas; i++) {
			rc = ec_table_build(&mfsa_g.dfas[i],
					    &mfsa_ecm,
					    &mfsa_ects[i]);
			if (rc) {
				for (uint32_t j = 0; j < i; j++)
					ec_table_free(&mfsa_ects[j]);
				ec_table_free(&ac_ect);
				ac_match_info_free(&match_info);
				mfsa_free(&mfsa_g);
				return rc;
			}
		}

		rc = linearize_v4(&ac_ecm, &ac_ect, &match_info,
				  &mfsa_ecm, mfsa_ects.data(),
				  mfsa_g.num_dfas,
				  mfsa_g.rule_ids,
				  always_run.data(),
				  (uint32_t)always_run.size(),
				  &blob_);

		for (uint32_t i = 0; i < mfsa_g.num_dfas; i++)
			ec_table_free(&mfsa_ects[i]);
		ec_table_free(&ac_ect);
		ac_match_info_free(&match_info);
		mfsa_free(&mfsa_g);
		return rc;
	}

	int simulate(const char *payload)
	{
		return linearize_v4_simulate(
			&blob_, (const uint8_t *)payload,
			(uint32_t)strlen(payload));
	}

	struct arena_blob blob_;
};

TEST_F(V4E2eTest, TwoRulesDistinctContentAndPcre)
{
	/* Rule 0: content="SELECT", pcre="UNION\s+SELECT" */
	/* Rule 1: content="../",    pcre="\.\.\/" */
	ASSERT_EQ(build_v4({
		{"SELECT", "UNION\\s+SELECT"},
		{"../", "\\.\\./"},
	}), ZDPI_OK);

	/* AC matches "SELECT" -> runs PCRE DFA 0 */
	EXPECT_EQ(simulate("UNION SELECT"), ZDPI_ACTION_DROP);
	/* AC matches "../" -> runs PCRE DFA 1 */
	EXPECT_EQ(simulate("../"), ZDPI_ACTION_DROP);
	/* No content match -> no PCRE runs -> PASS */
	EXPECT_EQ(simulate("safe payload"), ZDPI_ACTION_PASS);
}

TEST_F(V4E2eTest, CleanPayloadNeverRunsMFSA)
{
	ASSERT_EQ(build_v4({
		{"attack", "attack"},
		{"malware", "malware"},
	}), ZDPI_OK);

	/* Clean payload: no AC match -> skip all MFSA -> PASS */
	EXPECT_EQ(simulate("hello world safe data"),
		  ZDPI_ACTION_PASS);
}

TEST_F(V4E2eTest, ContentMatchButPcreNoMatch)
{
	/* Content "SELECT" matches, but the PCRE needs "UNION SELECT" */
	ASSERT_EQ(build_v4({
		{"SELECT", "UNION\\s+SELECT"},
	}), ZDPI_OK);

	/* AC false positive: content matches but PCRE doesn't */
	EXPECT_EQ(simulate("SELECT * FROM users"),
		  ZDPI_ACTION_PASS);
	/* Both AC and PCRE match */
	EXPECT_EQ(simulate("UNION SELECT * FROM users"),
		  ZDPI_ACTION_DROP);
}

TEST_F(V4E2eTest, AlwaysRunRuleNoContent)
{
	/* Rule 0: has content, Rule 1: no content (always-run) */
	ASSERT_EQ(build_v4({
		{"SELECT", "SELECT"},
		{"", "xyz"},	/* no content -> always-run */
	}), ZDPI_OK);

	/* No AC match for content, but "xyz" always runs -> DROP */
	EXPECT_EQ(simulate("xyz"), ZDPI_ACTION_DROP);
	/* Content match for SELECT -> also DROP */
	EXPECT_EQ(simulate("SELECT"), ZDPI_ACTION_DROP);
	/* Neither content match nor always-run pattern -> PASS */
	EXPECT_EQ(simulate("hello"), ZDPI_ACTION_PASS);
}

TEST_F(V4E2eTest, MultipleContentOverlap)
{
	ASSERT_EQ(build_v4({
		{"GET", "GET"},
		{"POST", "POST"},
		{"PUT", "PUT"},
	}), ZDPI_OK);

	EXPECT_EQ(simulate("GET /index"), ZDPI_ACTION_DROP);
	EXPECT_EQ(simulate("POST /form"), ZDPI_ACTION_DROP);
	EXPECT_EQ(simulate("PUT /file"), ZDPI_ACTION_DROP);
	EXPECT_EQ(simulate("DELETE /item"), ZDPI_ACTION_PASS);
}

TEST_F(V4E2eTest, RuleFileWithContent)
{
	/* Test parsing a rule file with content fields */
	struct zdpi_ruleset ruleset;
	int rc = ruleset_alloc(&ruleset, 64);
	ASSERT_EQ(rc, ZDPI_OK);
	rc = ruleset_parse_file(
		ZDPI_TEST_DATA_DIR "/rules/content_sample.rules",
		&ruleset);
	ASSERT_EQ(rc, ZDPI_OK);
	EXPECT_GE(ruleset.num_rules, 3u);

	/* Check that content fields were parsed */
	uint32_t rules_with_content = 0;
	for (uint32_t i = 0; i < ruleset.num_rules; i++) {
		if (ruleset.rules[i].num_contents > 0)
			rules_with_content++;
	}
	EXPECT_GE(rules_with_content, 3u);

	ruleset_free(&ruleset);
}
