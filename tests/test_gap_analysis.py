import datetime as dt
import decimal
import json
import unittest

from policy_sandbox.assessment.gap_analysis import (
    DISCLAIMER,
    ELIGIBLE,
    INELIGIBLE,
    GapAnalysisError,
    GapAnalyzer,
    PolicyVersion,
    UNDETERMINED,
    analyze_fixture,
)

EXPRESSION = "age >= 18 and degree in ['master','doctor'] and employed == True"
UNITS = {'age': 'years', 'benefit': 'CNY', 'income': 'CNY', 'rent': 'CNY',
         'commute_km': 'km'}


def person(person_id, facts=None, **extra):
    item = {'id': person_id, 'owner_id': person_id, 'facts': dict(facts or {})}
    item.update(extra)
    return item


class ThreeValuedEvaluationTests(unittest.TestCase):
    def setUp(self):
        self.analyzer = GapAnalyzer(
            PolicyVersion('v1', EXPRESSION), units=UNITS,
            default_benefit='1200', benefit_unit='CNY', capacity=20)

    def analyze(self, facts, **extra):
        return self.analyzer.analyze_people([person('p1', facts, **extra)]).people[0]

    def test_fully_known_eligible_is_determined(self):
        result = self.analyze({'age': 25, 'degree': 'master', 'employed': True})
        self.assertEqual(result.status, ELIGIBLE)
        self.assertTrue(result.determined)
        self.assertEqual(result.missing_facts, ())
        self.assertEqual(result.blocking_facts, ())
        self.assertEqual(result.potential_benefit, decimal.Decimal('1200.00'))

    def test_fully_known_ineligible_is_determined(self):
        result = self.analyze({'age': 17, 'degree': 'master', 'employed': True})
        self.assertEqual(result.status, INELIGIBLE)
        self.assertTrue(result.determined)
        # 确定不合格者不预留补贴
        self.assertIsNone(result.potential_benefit)

    def test_missing_fact_yields_unknown_not_ineligible(self):
        result = self.analyze({'age': 25, 'degree': 'master'})
        self.assertEqual(result.status, UNDETERMINED)
        self.assertFalse(result.determined)
        self.assertEqual([gap.fact for gap in result.missing_facts], ['employed'])
        self.assertTrue(result.missing_facts[0].blocking)

    def test_unknown_must_not_be_treated_as_failure(self):
        report = self.analyzer.analyze_people([
            person('a', {'age': 20}),
            person('b', {'age': 15, 'degree': 'doctor', 'employed': True}),
        ])
        statuses = {p.person_id: p.status for p in report.people}
        self.assertEqual(statuses, {'a': UNDETERMINED, 'b': INELIGIBLE})

    def test_multiple_missing_facts_one_person_all_listed(self):
        result = self.analyze({'age': 25})
        self.assertEqual(result.status, UNDETERMINED)
        self.assertEqual(
            sorted(gap.fact for gap in result.missing_facts),
            ['degree', 'employed'])
        self.assertEqual(set(result.blocking_facts), {'degree', 'employed'})

    def test_non_blocking_missing_when_known_clause_already_false(self):
        # age<18 已使整条 And 为假，degree/employed 缺失但不阻断——补它们也翻不了案
        result = self.analyze({'age': 16})
        self.assertEqual(result.status, INELIGIBLE)
        self.assertEqual(
            sorted(gap.fact for gap in result.missing_facts),
            ['degree', 'employed'])
        self.assertEqual(result.blocking_facts, ())
        self.assertTrue(any('当前不阻断结论' in text for text in result.explanations))

    def test_blocking_but_irrelevant_in_or_branch(self):
        analyzer = GapAnalyzer(PolicyVersion('v1', 'age >= 18 or income > 5000'),
                               units=UNITS)
        # age 已知且满足，income 缺失不应阻断
        result = analyzer.analyze_people([person('p1', {'age': 30})]).people[0]
        self.assertEqual(result.status, ELIGIBLE)
        self.assertEqual([gap.fact for gap in result.missing_facts], ['income'])
        self.assertFalse(result.missing_facts[0].blocking)

    def test_not_operator_three_valued(self):
        analyzer = GapAnalyzer(PolicyVersion('v1', 'not blacklisted'))
        result = analyzer.analyze_people([person('p1', {})]).people[0]
        self.assertEqual(result.status, UNDETERMINED)
        self.assertEqual(result.blocking_facts, ('blacklisted',))

    def test_none_value_treated_as_missing(self):
        result = self.analyze(
            {'age': 25, 'degree': None, 'employed': True})
        self.assertEqual(result.status, UNDETERMINED)
        self.assertEqual([gap.fact for gap in result.missing_facts], ['degree'])

    def test_type_error_becomes_unknown_not_crash(self):
        analyzer = GapAnalyzer(PolicyVersion('v1', 'age >= 18'))
        result = analyzer.analyze_people(
            [person('p1', {'age': 'twenty'})]).people[0]
        self.assertEqual(result.status, UNDETERMINED)


class BlockingWitnessTests(unittest.TestCase):
    def test_numeric_witness_for_lt(self):
        analyzer = GapAnalyzer(PolicyVersion('v1', 'income < 1000'))
        result = analyzer.analyze_people([person('p1', {})]).people[0]
        self.assertEqual(result.status, UNDETERMINED)
        self.assertEqual(result.blocking_facts, ('income',))

    def test_equality_witness(self):
        analyzer = GapAnalyzer(PolicyVersion('v1', "degree == 'doctor'"))
        result = analyzer.analyze_people([person('p1', {})]).people[0]
        self.assertEqual(result.blocking_facts, ('degree',))

    def test_not_in_witness(self):
        analyzer = GapAnalyzer(
            PolicyVersion('v1', "city not in ['beijing','shanghai']"))
        result = analyzer.analyze_people([person('p1', {})]).people[0]
        self.assertEqual(result.blocking_facts, ('city',))

    def test_bare_boolean_name_is_blocking(self):
        analyzer = GapAnalyzer(PolicyVersion('v1', 'employed'))
        result = analyzer.analyze_people([person('p1', {})]).people[0]
        self.assertEqual(result.blocking_facts, ('employed',))


class BudgetBoundTests(unittest.TestCase):
    def setUp(self):
        self.analyzer = GapAnalyzer(
            PolicyVersion('v1', EXPRESSION), units=UNITS,
            default_benefit='1200', benefit_unit='CNY', capacity=20)

    def test_bounds_with_unknown_population(self):
        report = self.analyzer.analyze_people([
            person('certain', {'age': 25, 'degree': 'master', 'employed': True}),
            person('pending', {'age': 25, 'degree': 'master'}),          # unknown
            person('rejected', {'age': 17, 'degree': 'master', 'employed': True}),
        ])
        budget = report.budget
        self.assertEqual(budget.certain_eligible_count, 1)
        self.assertEqual(budget.undetermined_count, 1)
        self.assertEqual(budget.determined_ineligible_count, 1)
        self.assertEqual(budget.headcount_lower, 1)
        self.assertEqual(budget.headcount_upper, 2)
        self.assertEqual(budget.lower_required, '1200.00')
        self.assertEqual(budget.upper_required, '2400.00')
        self.assertEqual(budget.reserve_recommended, '2400.00')

    def test_no_double_counting_with_multiple_missing_facts(self):
        # 同一人缺两个事实，潜在补贴只能计一次
        report = self.analyzer.analyze_people([
            person('p1', {'age': 25}),
        ])
        self.assertEqual(report.totals['blocking_fact_records'], 2)
        self.assertEqual(report.budget.headcount_upper, 1)
        self.assertEqual(report.budget.upper_required, '1200.00')

    def test_duplicate_person_id_counted_once(self):
        report = self.analyzer.analyze_people([
            person('p1', {'age': 25, 'degree': 'master', 'employed': True}),
            person('p1', {'age': 25, 'degree': 'master', 'employed': True}),
        ])
        self.assertEqual(report.totals['people'], 1)
        self.assertEqual(report.budget.upper_required, '1200.00')

    def test_per_person_amount_override(self):
        report = self.analyzer.analyze_people([
            person('p1', {'age': 25, 'degree': 'master', 'employed': True},
                   amount='1500'),
            person('p2', {'age': 30}),
        ])
        self.assertEqual(report.budget.upper_required, '2700.00')

    def test_capacity_risk_and_remaining(self):
        analyzer = GapAnalyzer(
            PolicyVersion('v1', 'age >= 18 and employed'), units=UNITS,
            default_benefit='100', capacity=2)
        report = analyzer.analyze_people([
            person('a', {'age': 20}),
            person('b', {'age': 21}),
            person('c', {'age': 22}),
        ])
        self.assertEqual(report.budget.undetermined_count, 3)
        self.assertTrue(report.budget.capacity_at_risk)
        # 尚无确定合格者，名义剩余即满容量；最坏情形（3 人全合格）下剩余为 0
        self.assertEqual(report.budget.remaining_capacity, 2)
        self.assertEqual(report.budget.free_capacity_worst_case, 0)
        self.assertEqual(report.budget.max_possible_accepted, 2)
        self.assertEqual(report.budget.headcount_upper, 3)

    def test_capacity_not_at_risk_when_within(self):
        analyzer = GapAnalyzer(
            PolicyVersion('v1', 'age >= 18'), units=UNITS,
            default_benefit='100', capacity=5)
        report = analyzer.analyze_people([person('a', {'age': 20})])
        self.assertFalse(report.budget.capacity_at_risk)
        self.assertEqual(report.budget.max_possible_accepted, 1)


class AggregationTests(unittest.TestCase):
    def setUp(self):
        self.analyzer = GapAnalyzer(
            PolicyVersion('v1', EXPRESSION), units=UNITS,
            default_benefit='1200', capacity=20, group_field='degree')

    def test_by_fact_type_counts_and_verification_items(self):
        report = self.analyzer.analyze_people([
            person('a', {'age': 25}),                                   # degree, employed
            person('b', {'age': 25, 'degree': 'master'}),               # employed
            person('c', {'age': 16}),                                   # 不阻断的 degree, employed
        ])
        by_fact = report.by_fact_type
        self.assertEqual(by_fact['employed']['missing_people'], 3)
        self.assertEqual(by_fact['employed']['blocking_people'], 2)
        self.assertEqual(by_fact['employed']['non_blocking_people'], 1)
        self.assertEqual(by_fact['employed']['verification_items'], 3)
        self.assertEqual(by_fact['employed']['unit'], None)
        self.assertEqual(by_fact['degree']['missing_people'], 2)
        self.assertEqual(by_fact['degree']['blocking_people'], 1)
        # 待核量按阻断事实条目计
        self.assertEqual(
            sum(len(p.blocking_facts) for p in report.people), 3)

    def test_by_group_breakdown(self):
        report = self.analyzer.analyze_people([
            person('a', {'age': 25, 'degree': 'master', 'employed': True}),
            person('b', {'age': 25, 'degree': 'master'}),
            person('c', {'age': 25, 'degree': 'doctor'}),
        ])
        groups = report.by_group
        self.assertEqual(groups['master']['people'], 2)
        self.assertEqual(groups['master']['eligible'], 1)
        self.assertEqual(groups['master']['unknown'], 1)
        self.assertEqual(groups['master']['verification_items'], 1)
        self.assertEqual(groups['doctor']['unknown'], 1)

    def test_group_fallback_to_explicit_group_field(self):
        analyzer = GapAnalyzer(PolicyVersion('v1', 'age >= 18'))
        report = analyzer.analyze_people([
            person('a', {'age': 20}, group='north'),
            person('b', {'age': 15}, group='south'),
        ])
        self.assertEqual(set(report.by_group), {'north', 'south'})


class UnitTests(unittest.TestCase):
    def test_unit_mismatch_flagged_on_comparison(self):
        analyzer = GapAnalyzer(
            PolicyVersion('v1', 'income <= rent'),
            units={'income': 'CNY', 'rent': 'km'})
        self.assertTrue(any('unit_mismatch:income:rent' in w
                            for w in analyzer.unit_warnings))

    def test_matching_units_no_warning(self):
        analyzer = GapAnalyzer(
            PolicyVersion('v1', 'income <= rent'),
            units={'income': 'CNY', 'rent': 'CNY'})
        self.assertEqual(analyzer.unit_warnings, [])

    def test_gap_record_carries_unit_metadata(self):
        analyzer = GapAnalyzer(PolicyVersion('v1', 'income < 1000'),
                               units={'income': 'CNY'})
        result = analyzer.analyze_people([person('p1', {})]).people[0]
        self.assertEqual(result.missing_facts[0].unit, 'CNY')

    def test_budget_currency_unit_propagated(self):
        analyzer = GapAnalyzer(PolicyVersion('v1', 'age >= 18'),
                               units={'benefit': 'CNY'}, default_benefit='10')
        report = analyzer.analyze_people([person('p1', {})])
        self.assertEqual(report.budget.currency_unit, 'CNY')
        self.assertEqual(report.people[0].benefit_unit, 'CNY')


class PolicyVersionTests(unittest.TestCase):
    def setUp(self):
        self.versions = (
            PolicyVersion('v1', "degree in ['bachelor']",
                          dt.date(2025, 1, 1), dt.date(2025, 12, 31)),
            PolicyVersion('v2', "degree in ['master','doctor']",
                          dt.date(2026, 1, 1), None),
        )
        self.analyzer = GapAnalyzer(self.versions, default_benefit='1000')

    def test_old_application_uses_old_version(self):
        result = self.analyzer.analyze_people([
            person('old', {'degree': 'bachelor'}, effective_from='2025-06-01')
        ]).people[0]
        self.assertEqual(result.applied_version, 'v1')
        self.assertEqual(result.status, ELIGIBLE)

    def test_new_application_uses_new_version(self):
        result = self.analyzer.analyze_people([
            person('new', {'degree': 'bachelor'}, effective_from='2026-11-16')
        ]).people[0]
        self.assertEqual(result.applied_version, 'v2')
        self.assertEqual(result.status, INELIGIBLE)

    def test_missing_fact_version_trace(self):
        result = self.analyzer.analyze_people([
            person('p1', {}, effective_from='2026-11-16')
        ]).people[0]
        self.assertEqual(result.applied_version, 'v2')
        self.assertEqual(result.missing_facts[0].appears_in_versions, ('v1', 'v2'))

    def test_no_active_version_warns_and_undetermined(self):
        report = self.analyzer.analyze_people([
            person('p1', {'degree': 'master'}, effective_from='2024-01-01')
        ])
        self.assertEqual(report.people[0].status, UNDETERMINED)
        self.assertTrue(any('no_active_policy_version' in w
                            for w in report.version_warnings))

    def test_duplicate_version_identifier_rejected(self):
        with self.assertRaises(GapAnalysisError):
            GapAnalyzer([
                PolicyVersion('v1', 'age >= 18'),
                PolicyVersion('v1', 'age >= 30'),
            ])

    def test_unsafe_expression_rejected(self):
        with self.assertRaises(GapAnalysisError):
            GapAnalyzer(PolicyVersion('v1', '__import__("os")'))


class FixtureEntryPointTests(unittest.TestCase):
    def test_analyze_fixture_structure(self):
        fixture = {
            'context': {
                'expression': EXPRESSION,
                'benefit': '1200',
                'capacity': 20,
                'three_valued': True,
                'units': UNITS,
            },
            'items': [
                {'id': 'person-1', 'owner_id': 'person-1',
                 'facts': {'age': 25, 'degree': 'master', 'employed': True},
                 'demand': 1, 'amount': '1200',
                 'effective_from': '2026-11-16', 'request_key': 'acceptance-1'},
                {'id': 'person-2', 'owner_id': 'person-2',
                 'facts': {'age': 25, 'degree': 'master'},
                 'effective_from': '2026-11-16'},
            ],
        }
        report = analyze_fixture(fixture)
        payload = report.as_dict()
        self.assertEqual(payload['totals']['people'], 2)
        self.assertEqual(payload['totals']['eligible'], 1)
        self.assertEqual(payload['totals']['unknown'], 1)
        self.assertEqual(payload['budget']['upper_required'], '2400.00')
        self.assertEqual(payload['people'][1]['blocking_facts'], ['employed'])
        self.assertIn('不构成正式资格认定', payload['disclaimer'])
        # 输出可 JSON 序列化
        json.dumps(payload, ensure_ascii=False)

    def test_policy_versions_in_context(self):
        context = {
            'units': UNITS,
            'benefit': '800',
            'policy_versions': [
                {'version': 'old', 'expression': 'age >= 16',
                 'effective_from': '2025-01-01', 'effective_to': '2025-12-31'},
                {'version': 'new', 'expression': 'age >= 18',
                 'effective_from': '2026-01-01'},
            ],
        }
        analyzer = GapAnalyzer.from_context(context)
        report = analyzer.analyze_people([
            person('a', {'age': 17}, effective_from='2025-06-01'),
            person('b', {'age': 17}, effective_from='2026-06-01'),
        ])
        versions = {p.person_id: p.applied_version for p in report.people}
        self.assertEqual(versions, {'a': 'old', 'b': 'new'})
        statuses = {p.person_id: p.status for p in report.people}
        self.assertEqual(statuses['a'], ELIGIBLE)
        self.assertEqual(statuses['b'], INELIGIBLE)


class ExpressionFeatureTests(unittest.TestCase):
    def test_chained_comparison_three_valued(self):
        analyzer = GapAnalyzer(PolicyVersion('v1', '18 <= age < 60'))
        result = analyzer.analyze_people([person('p1', {})]).people[0]
        self.assertEqual(result.status, UNDETERMINED)
        self.assertEqual(result.blocking_facts, ('age',))

    def test_chained_comparison_known_ineligible(self):
        analyzer = GapAnalyzer(PolicyVersion('v1', '18 <= age < 60'))
        result = analyzer.analyze_people(
            [person('p1', {'age': 65})]).people[0]
        self.assertEqual(result.status, INELIGIBLE)

    def test_arithmetic_in_expression(self):
        analyzer = GapAnalyzer(PolicyVersion('v1', 'income - rent > 1000'))
        result = analyzer.analyze_people(
            [person('p1', {'income': 5000, 'rent': 3000})]).people[0]
        self.assertEqual(result.status, ELIGIBLE)
        pending = analyzer.analyze_people(
            [person('p2', {'income': 5000})]).people[0]
        self.assertEqual(pending.status, UNDETERMINED)
        self.assertEqual(set(pending.blocking_facts), {'rent'})

    def test_division_by_zero_becomes_unknown(self):
        analyzer = GapAnalyzer(PolicyVersion('v1', 'income / dependents > 100'))
        result = analyzer.analyze_people(
            [person('p1', {'income': 5000, 'dependents': 0})]).people[0]
        self.assertEqual(result.status, UNDETERMINED)

    def test_mixed_budget_decimal_precision(self):
        analyzer = GapAnalyzer(PolicyVersion('v1', 'age >= 18'),
                               default_benefit='333.33')
        report = analyzer.analyze_people([
            person('a', {'age': 20}),
            person('b', {}),
            person('c', {}),
        ])
        self.assertEqual(report.budget.lower_required, '333.33')
        self.assertEqual(report.budget.upper_required, '999.99')

    def test_effective_boundary_is_inclusive(self):
        versions = (
            PolicyVersion('v1', 'age >= 16', None, dt.date(2025, 12, 31)),
            PolicyVersion('v2', 'age >= 18', dt.date(2026, 1, 1), None),
        )
        analyzer = GapAnalyzer(versions)
        last_day = analyzer.analyze_people([
            person('a', {'age': 17}, effective_from='2025-12-31')]).people[0]
        first_day = analyzer.analyze_people([
            person('b', {'age': 17}, effective_from='2026-01-01')]).people[0]
        self.assertEqual(last_day.applied_version, 'v1')
        self.assertEqual(first_day.applied_version, 'v2')
        self.assertEqual(last_day.status, ELIGIBLE)
        self.assertEqual(first_day.status, INELIGIBLE)

    def test_empty_population_bounds_zero(self):
        report = GapAnalyzer(
            PolicyVersion('v1', 'age >= 18'), default_benefit='100',
            capacity=5).analyze_people([])
        self.assertEqual(report.budget.lower_required, '0.00')
        self.assertEqual(report.budget.upper_required, '0.00')
        self.assertEqual(report.budget.remaining_capacity, 5)
        self.assertFalse(report.budget.capacity_at_risk)

    def test_explanation_mentions_each_missing_fact(self):
        analyzer = GapAnalyzer(
            PolicyVersion('v1', "age >= 18 and degree in ['master']"))
        result = analyzer.analyze_people([person('p1', {})]).people[0]
        joined = ' '.join(result.explanations)
        self.assertIn('age', joined)
        self.assertIn('degree', joined)
        self.assertIn('阻断', joined)

    def test_no_benefit_configured_bounds_count_only(self):
        analyzer = GapAnalyzer(PolicyVersion('v1', 'age >= 18'))
        report = analyzer.analyze_people([person('a', {}), person('b', {})])
        self.assertIsNone(report.budget.benefit_per_person)
        self.assertEqual(report.budget.lower_required, '0.00')
        self.assertEqual(report.budget.upper_required, '0.00')
        self.assertEqual(report.budget.headcount_upper, 2)

    def test_versions_with_no_overlap_choice(self):
        analyzer = GapAnalyzer(PolicyVersion('v1', 'age >= 18'))
        self.assertEqual(analyzer.select_version(None).version, 'v1')

    def test_multiple_missing_with_arithmetic_all_blocking(self):
        expr = ("age >= 18 and degree in ['master','doctor'] "
                "and employed == True and income - rent >= 2000")
        analyzer = GapAnalyzer(PolicyVersion('v2026', expr))
        result = analyzer.analyze_people([person('p1', {'age': 28})]).people[0]
        self.assertEqual(result.status, UNDETERMINED)
        self.assertEqual(set(result.blocking_facts),
                         {'degree', 'employed', 'income', 'rent'})
        # 同一人四笔缺口只预留一笔补贴
        report = analyzer.analyze_people([person('p1', {'age': 28})])
        self.assertEqual(report.budget.headcount_upper, 1)

    def test_partial_arithmetic_fact_blocking(self):
        analyzer = GapAnalyzer(
            PolicyVersion('v1', 'income - rent >= 2000'),
            units={'income': 'CNY/month', 'rent': 'CNY/month'})
        result = analyzer.analyze_people(
            [person('p1', {'income': 8000})]).people[0]
        self.assertEqual(result.blocking_facts, ('rent',))

    def test_and_all_missing_every_fact_blocks(self):
        analyzer = GapAnalyzer(PolicyVersion(
            'v1', "age >= 18 and degree in ['master'] and employed == True"))
        result = analyzer.analyze_people([person('p1', {})]).people[0]
        self.assertEqual(set(result.blocking_facts),
                         {'age', 'degree', 'employed'})

    def test_or_all_missing_no_individual_fact_blocks(self):
        analyzer = GapAnalyzer(PolicyVersion('v1', 'age >= 18 or employed == True'))
        result = analyzer.analyze_people([person('p1', {})]).people[0]
        self.assertEqual(result.status, UNDETERMINED)
        self.assertEqual(result.blocking_facts, ())
        # 缺口仍需补证，只是没有哪一项单独决定成败
        self.assertEqual(
            sorted(g.fact for g in result.missing_facts), ['age', 'employed'])

    def test_nested_or_branch_satisfied_other_missing_non_blocking(self):
        expr = ("(age >= 18 and degree in ['master']) "
                "or (employed == True and income > 5000)")
        analyzer = GapAnalyzer(PolicyVersion('v1', expr))
        result = analyzer.analyze_people(
            [person('p1', {'age': 20, 'degree': 'master'})]).people[0]
        self.assertEqual(result.status, ELIGIBLE)
        self.assertEqual(result.blocking_facts, ())


class AdvisoryOnlyTests(unittest.TestCase):
    def test_inputs_are_not_mutated(self):
        analyzer = GapAnalyzer(PolicyVersion('v1', EXPRESSION),
                               default_benefit='1200')
        item = person('p1', {'age': 25})
        snapshot = json.dumps(item, sort_keys=True, default=str)
        analyzer.analyze_people([item])
        self.assertEqual(json.dumps(item, sort_keys=True, default=str), snapshot)

    def test_disclaimer_present(self):
        report = GapAnalyzer(PolicyVersion('v1', 'age >= 18')).analyze_people([])
        self.assertEqual(report.disclaimer, DISCLAIMER)

    def test_unknown_people_have_potential_but_no_determined_amount(self):
        analyzer = GapAnalyzer(PolicyVersion('v1', 'age >= 18'),
                               default_benefit='500')
        result = analyzer.analyze_people([person('p1', {})]).people[0]
        self.assertEqual(result.status, UNDETERMINED)
        self.assertEqual(result.potential_benefit, decimal.Decimal('500.00'))
        # 潜在金额只出现在预算上界，不出现在任何“确定发放”字段
        self.assertNotIn('granted_amount', result.as_dict())


if __name__ == '__main__':
    unittest.main()
