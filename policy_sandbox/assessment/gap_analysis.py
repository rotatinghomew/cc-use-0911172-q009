"""资料缺口分析（三值逻辑 / Kleene 逻辑）。

本模块只服务于补证优先级与预算预留，不改变任何正式资格结论，也不产生
确定的发放金额。对每个申请人，基于其已知事实与适用版本的规则表达式给出：

* ``eligible``   —— 已知事实已足以确定合格；
* ``ineligible`` —— 已知事实已足以确定不合格（补证也无法翻转的确定性结论）；
* ``unknown``    —— 结论取决于一个或多个缺失事实，需要补证。

预算以“每名申请人最多一笔潜在补贴”计，上下界分别对应全部待核人补证后
合格 / 全部不合格两种极端情形，因而同一人的同一笔潜在补贴不会被重复计入。
"""
from __future__ import annotations

import ast
import datetime as dt
import decimal
from collections import defaultdict
from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Sequence

from ..rule_language.policy_runtime import PolicyRuntime

TRUE = 'true'
FALSE = 'false'
UNKNOWN = 'unknown'

ELIGIBLE = 'eligible'
INELIGIBLE = 'ineligible'
UNDETERMINED = 'unknown'


class GapAnalysisError(ValueError):
    pass


@dataclass(frozen=True)
class PolicyVersion:
    """规则表达式的一个生效版本。"""
    version: str
    expression: str
    effective_from: dt.date | None = None
    effective_to: dt.date | None = None

    def active_on(self, day: dt.date | None) -> bool:
        if day is None:
            return self.effective_from is None
        if self.effective_from is not None and day < self.effective_from:
            return False
        if self.effective_to is not None and day > self.effective_to:
            return False
        return True


class _KleeneEvaluator:
    """在 PolicyRuntime 的安全 AST 白名单内执行三值逻辑求值。"""

    ALLOWED = PolicyRuntime.ALLOWED

    def __init__(self, units: Mapping[str, str] | None = None):
        self.units = dict(units or {})
        self.unit_errors: list[str] = []

    def compile(self, expression: str):
        tree = ast.parse(expression, mode='eval')
        for node in ast.walk(tree):
            if not isinstance(node, self.ALLOWED):
                raise GapAnalysisError('unsafe_policy_expression')
        return tree, sorted({n.id for n in ast.walk(tree) if isinstance(n, ast.Name)})

    def check_units(self, tree: ast.AST) -> Sequence[str]:
        """同一比较两侧若都登记了单位，单位必须一致。"""
        errors: list[str] = []
        compare_nodes = (ast.Eq, ast.NotEq, ast.Lt, ast.LtE, ast.Gt, ast.GtE)
        for node in ast.walk(tree):
            if isinstance(node, ast.Compare):
                sides = [node.left, *node.comparators]
                for op, left, right in zip(node.ops, sides, sides[1:]):
                    if not isinstance(op, compare_nodes):
                        continue
                    left_name = left.id if isinstance(left, ast.Name) else None
                    right_name = right.id if isinstance(right, ast.Name) else None
                    if (left_name and right_name and left_name in self.units
                            and right_name in self.units
                            and self.units[left_name] != self.units[right_name]):
                        errors.append(
                            f'unit_mismatch:{left_name}:{right_name}:'
                            f'{self.units[left_name]}!={self.units[right_name]}')
        return errors

    def eval_tree(self, node: ast.AST, facts: Mapping[str, Any]) -> str:
        if isinstance(node, ast.Expression):
            return self.eval_tree(node.body, facts)
        if isinstance(node, ast.Constant):
            return TRUE if bool(node.value) else FALSE
        if isinstance(node, ast.Name):
            if node.id not in facts or facts[node.id] is None:
                return UNKNOWN
            return TRUE if bool(facts[node.id]) else FALSE
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            value = self.eval_tree(node.operand, facts)
            return UNKNOWN if value == UNKNOWN else (FALSE if value == TRUE else TRUE)
        if isinstance(node, ast.BoolOp):
            values = [self.eval_tree(child, facts) for child in node.values]
            if isinstance(node.op, ast.And):
                if any(value == FALSE for value in values):
                    return FALSE
                return UNKNOWN if any(value == UNKNOWN for value in values) else TRUE
            if isinstance(node.op, ast.Or):
                if any(value == TRUE for value in values):
                    return TRUE
                return UNKNOWN if any(value == UNKNOWN for value in values) else FALSE
        if isinstance(node, ast.Compare):
            return self._eval_compare(node, facts)
        if isinstance(node, ast.BinOp):
            return self._eval_binop(node, facts)
        raise GapAnalysisError('unsupported_expression_node')

    def _eval_compare(self, node: ast.Compare, facts: Mapping[str, Any]) -> str:
        left = self._operand(node.left, facts)
        current = left
        results: list[str] = []
        for op, comparator_node in zip(node.ops, node.comparators):
            right = self._operand(comparator_node, facts)
            results.append(self._apply_operator(op, current, right))
            current = right
        if any(value == UNKNOWN for value in results):
            return UNKNOWN
        return TRUE if all(value == TRUE for value in results) else FALSE

    def _operand(self, node: ast.AST, facts: Mapping[str, Any]):
        if isinstance(node, ast.Name):
            return UNKNOWN if (node.id not in facts or facts[node.id] is None) else facts[node.id]
        if isinstance(node, ast.Constant):
            return node.value
        if isinstance(node, (ast.List, ast.Tuple)):
            values = []
            for child in node.elts:
                value = self._operand(child, facts)
                if value is UNKNOWN:
                    return UNKNOWN
                values.append(value)
            return values
        if isinstance(node, ast.BinOp):
            return self._binop_value(node, facts)
        raise GapAnalysisError('unsupported_expression_node')

    def _binop_value(self, node: ast.BinOp, facts: Mapping[str, Any]):
        left = self._operand(node.left, facts)
        right = self._operand(node.right, facts)
        if left is UNKNOWN or right is UNKNOWN:
            return UNKNOWN
        try:
            if isinstance(node.op, ast.Add):
                return left + right
            if isinstance(node.op, ast.Sub):
                return left - right
            if isinstance(node.op, ast.Mult):
                return left * right
            if isinstance(node.op, ast.Div):
                return left / right
        except (TypeError, ValueError, ZeroDivisionError):
            return UNKNOWN
        raise GapAnalysisError('unsupported_expression_node')

    def _apply_operator(self, op: ast.AST, left: Any, right: Any) -> str:
        if left is UNKNOWN or right is UNKNOWN:
            return UNKNOWN
        try:
            if isinstance(op, ast.Eq):
                result = left == right
            elif isinstance(op, ast.NotEq):
                result = left != right
            elif isinstance(op, ast.Lt):
                result = left < right
            elif isinstance(op, ast.LtE):
                result = left <= right
            elif isinstance(op, ast.Gt):
                result = left > right
            elif isinstance(op, ast.GtE):
                result = left >= right
            elif isinstance(op, ast.In):
                result = left in right
            elif isinstance(op, ast.NotIn):
                result = left not in right
            else:
                raise GapAnalysisError('unsupported_expression_node')
        except TypeError:
            # 类型不兼容属于数据质量问题，在补证前同样无法定论。
            return UNKNOWN
        return TRUE if result else FALSE

    def _eval_binop(self, node: ast.BinOp, facts: Mapping[str, Any]) -> str:
        value = self._binop_value(node, facts)
        if value is UNKNOWN:
            return UNKNOWN
        return TRUE if bool(value) else FALSE


@dataclass(frozen=True)
class FactGap:
    """单个缺失事实的缺口描述。"""
    fact: str
    blocking: bool
    unit: str | None = None
    appears_in_versions: tuple[str, ...] = ()


@dataclass
class PersonGapAnalysis:
    person_id: str
    owner_id: str
    group: str
    status: str                      # eligible / ineligible / unknown
    applied_version: str | None
    evaluated_on: str | None
    known_facts: Mapping[str, Any]
    missing_facts: tuple[FactGap, ...]
    blocking_facts: tuple[str, ...]
    determined: bool
    explanations: tuple[str, ...]
    benefit_unit: str | None
    potential_benefit: decimal.Decimal | None   # 仅作预算预留的潜在单笔金额
    record_key: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            'person_id': self.person_id,
            'owner_id': self.owner_id,
            'group': self.group,
            'status': self.status,
            'applied_version': self.applied_version,
            'evaluated_on': self.evaluated_on,
            'known_facts': dict(self.known_facts),
            'missing_facts': [
                {'fact': item.fact, 'blocking': item.blocking, 'unit': item.unit,
                 'appears_in_versions': list(item.appears_in_versions)}
                for item in self.missing_facts
            ],
            'blocking_facts': list(self.blocking_facts),
            'determined': self.determined,
            'explanations': list(self.explanations),
            'benefit_unit': self.benefit_unit,
            'potential_benefit': None if self.potential_benefit is None else str(self.potential_benefit),
            'record_key': self.record_key,
        }


@dataclass(frozen=True)
class BudgetBounds:
    currency_unit: str | None
    benefit_per_person: str | None
    lower_required: str
    upper_required: str
    reserve_recommended: str
    certain_eligible_count: int
    undetermined_count: int
    determined_ineligible_count: int
    headcount_lower: int
    headcount_upper: int
    capacity: int | None
    remaining_capacity: int | None
    free_capacity_worst_case: int | None
    capacity_at_risk: bool
    max_possible_accepted: int | None

    def as_dict(self) -> dict[str, Any]:
        return {
            'currency_unit': self.currency_unit,
            'benefit_per_person': self.benefit_per_person,
            'lower_required': self.lower_required,
            'upper_required': self.upper_required,
            'reserve_recommended': self.reserve_recommended,
            'certain_eligible_count': self.certain_eligible_count,
            'undetermined_count': self.undetermined_count,
            'determined_ineligible_count': self.determined_ineligible_count,
            'headcount_lower': self.headcount_lower,
            'headcount_upper': self.headcount_upper,
            'capacity': self.capacity,
            'remaining_capacity': self.remaining_capacity,
            'free_capacity_worst_case': self.free_capacity_worst_case,
            'capacity_at_risk': self.capacity_at_risk,
            'max_possible_accepted': self.max_possible_accepted,
        }


@dataclass
class GapAnalysisReport:
    generated_at: str
    people: list[PersonGapAnalysis]
    by_fact_type: Mapping[str, Mapping[str, Any]]
    by_group: Mapping[str, Mapping[str, Any]]
    budget: BudgetBounds
    unit_warnings: tuple[str, ...]
    version_warnings: tuple[str, ...]
    totals: Mapping[str, int]
    disclaimer: str

    def as_dict(self) -> dict[str, Any]:
        return {
            'generated_at': self.generated_at,
            'totals': dict(self.totals),
            'by_fact_type': {key: dict(value) for key, value in self.by_fact_type.items()},
            'by_group': {key: dict(value) for key, value in self.by_group.items()},
            'budget': self.budget.as_dict(),
            'unit_warnings': list(self.unit_warnings),
            'version_warnings': list(self.version_warnings),
            'people': [person.as_dict() for person in self.people],
            'disclaimer': self.disclaimer,
        }


DISCLAIMER = (
    '本报告仅用于补证优先级排序与预算预留，不构成正式资格认定，不产生确定的发放金额；'
    'unknown 表示结论依赖待补事实，不得按不合格处理。'
)


class GapAnalyzer:
    """资料缺口分析器。"""

    def __init__(self,
                 versions: Sequence[PolicyVersion] | PolicyVersion | None = None,
                 units: Mapping[str, str] | None = None,
                 default_benefit: Any = None,
                 benefit_unit: str | None = None,
                 capacity: int | None = None,
                 group_field: str | None = None):
        self.versions = self._normalize_versions(versions)
        self.units = dict(units or {})
        self.default_benefit = (None if default_benefit is None
                                else decimal.Decimal(str(default_benefit)))
        self.benefit_unit = benefit_unit or self.units.get('benefit')
        self.capacity = None if capacity is None else int(capacity)
        self.group_field = group_field
        self._compiled: dict[str, tuple[ast.AST, tuple[str, ...]]] = {}
        self._evaluator = _KleeneEvaluator(self.units)
        self._current_facts: Mapping[str, Any] = {}
        self.unit_warnings: list[str] = []
        self.version_warnings: list[str] = []
        for version in self.versions:
            tree, names = self._evaluator.compile(version.expression)
            self._compiled[version.version] = (tree, tuple(names))
            self.unit_warnings.extend(self._evaluator.check_units(tree))

    @staticmethod
    def _normalize_versions(versions: Any) -> tuple[PolicyVersion, ...]:
        if versions is None:
            return (PolicyVersion('default', 'age >= 18'),)
        if isinstance(versions, PolicyVersion):
            return (versions,)
        normalized = tuple(versions)
        if not normalized:
            raise GapAnalysisError('at least one policy version is required')
        identifiers = [item.version for item in normalized]
        if len(set(identifiers)) != len(identifiers):
            raise GapAnalysisError('duplicate policy version identifier')
        return normalized

    @classmethod
    def from_context(cls, context: Mapping[str, Any]) -> 'GapAnalyzer':
        units = context.get('units') or {}
        raw_versions = context.get('policy_versions')
        if raw_versions:
            versions = []
            for index, item in enumerate(raw_versions):
                versions.append(PolicyVersion(
                    str(item.get('version', f'v{index + 1}')),
                    str(item['expression']),
                    _as_date(item.get('effective_from')),
                    _as_date(item.get('effective_to')),
                ))
        else:
            versions = (PolicyVersion(str(context.get('policy_version', 'default')),
                                      str(context.get('expression', 'age >= 18')),
                                      _as_date(context.get('effective_from')),
                                      _as_date(context.get('effective_to'))),)
        return cls(
            versions=versions,
            units=units,
            default_benefit=context.get('benefit'),
            benefit_unit=units.get('benefit'),
            capacity=context.get('capacity'),
            group_field=context.get('group_field'),
        )

    def select_version(self, evaluation_day: dt.date | None) -> PolicyVersion | None:
        active = [version for version in self.versions if version.active_on(evaluation_day)]
        if not active:
            return None
        return sorted(active, key=lambda item: (
            item.effective_from or dt.date.min, item.version))[-1]

    def analyze_people(self, people: Iterable[Mapping[str, Any]],
                       now: dt.datetime | None = None) -> GapAnalysisReport:
        moment = now or dt.datetime.now(dt.timezone.utc)
        analyses: list[PersonGapAnalysis] = []
        seen: set[str] = set()
        for position, raw in enumerate(people):
            person = self._dedupe(raw, position, seen)
            if person is None:
                continue
            analyses.append(self._analyze_one(person))
        return self._build_report(analyses, moment)

    def _dedupe(self, raw: Mapping[str, Any], position: int, seen: set[str]):
        person = dict(raw)
        person_id = str(person.get('id') or person.get('person_id') or f'person-{position}')
        if person_id in seen:
            return None
        seen.add(person_id)
        person['id'] = person_id
        return person

    def _analyze_one(self, person: Mapping[str, Any]) -> PersonGapAnalysis:
        person_id = str(person['id'])
        owner_id = str(person.get('owner_id') or person_id)
        group = self._group_of(person)
        facts = dict(person.get('facts') or {})
        evaluation_day = _as_date(person.get('effective_from'))
        version = self.select_version(evaluation_day)
        if version is None:
            self.version_warnings.append(
                f'{person_id}:no_active_policy_version_on:{evaluation_day or "unspecified"}')
            return self._undetermined(person_id, owner_id, group, facts, None, evaluation_day,
                                      person, ('no_active_policy_version',))
        tree, names = self._compiled[version.version]
        missing_names = tuple(sorted(
            name for name in names if name not in facts or facts[name] is None))
        tri = self._evaluator.eval_tree(tree, facts)
        explanations = [f'policy_version={version.version}',
                        f'expression={version.expression}']
        if tri == TRUE:
            status = ELIGIBLE
            explanations.append('已知事实满足全部合取条件，资格已确定为合格')
        elif tri == FALSE:
            status = INELIGIBLE
            explanations.append('已知事实已使规则确定为假，补证缺失事实无法翻转该结论')
        else:
            status = UNDETERMINED
            explanations.append('规则结论依赖缺失事实，需补证后才能定论')
        blocking = self._blocking_facts(version, tree, facts, missing_names)
        fact_gaps = tuple(
            FactGap(
                fact=name,
                blocking=name in blocking,
                unit=self.units.get(name),
                appears_in_versions=tuple(sorted(
                    version.version for version in self.versions
                    if name in self._compiled[version.version][1])),
            )
            for name in missing_names)
        explanations.extend(
            f'缺失事实 {item.fact}' + ('（阻断资格，必须补证）' if item.blocking
                                  else '（出现在表达式中但当前不阻断结论）')
            for item in fact_gaps)
        potential_benefit = self._potential_benefit(person, status)
        return PersonGapAnalysis(
            person_id=person_id,
            owner_id=owner_id,
            group=group,
            status=status,
            applied_version=version.version,
            evaluated_on=evaluation_day.isoformat() if evaluation_day else None,
            known_facts=facts,
            missing_facts=fact_gaps,
            blocking_facts=tuple(sorted(blocking)),
            determined=status != UNDETERMINED,
            explanations=tuple(explanations),
            benefit_unit=self.benefit_unit,
            potential_benefit=potential_benefit,
            record_key=person.get('request_key'),
        )

    def _group_of(self, person: Mapping[str, Any]) -> str:
        if not self.group_field:
            return str(person.get('group') or 'default')
        facts = person.get('facts') or {}
        if self.group_field in facts:
            return str(facts[self.group_field])
        if self.group_field in person:
            return str(person[self.group_field])
        return 'unspecified'

    def _blocking_facts(self, version: PolicyVersion, tree: ast.AST,
                        facts: Mapping[str, Any], missing_names: Sequence[str]) -> set[str]:
        """区分阻断性缺失与无关缺失。

        先为全部缺失事实构造类型感知的“证人环境”：若存在一组补证取值可让
        整条表达式在其余已知事实不变时变为真，则这些缺失都属于当前阻断项
        （不补证就无法合格）；反之（表达式已被已知事实钉死为假，任何取值
        都翻不了案）则没有阻断项。
        """
        if not missing_names:
            return set()
        if self._evaluator.eval_tree(tree, facts) == FALSE:
            return set()
        self._current_facts = facts
        constraints = self._collect_constraints(tree)
        negated = self._collect_negated_names(tree)
        witness_lists = {
            name: self._witness_values(
                name, constraints.get(name, ()), negated=name in negated)
            for name in missing_names}
        if any(not values for values in witness_lists.values()):
            return set(missing_names)
        completion = self._satisfying_completion(tree, facts, witness_lists)
        if completion is None:
            # 启发式证人未能构造出合格组合，但三值结果为 unknown 而非 false，
            # 说明理论上存在可让表达式成立的补证取值；保守起见全部计为阻断项，
            # 宁可多排补证工作量，也不低估复核量。
            return set(missing_names)
        # 表达式可被补证满足。逐项判定：若把该缺失固定为“不满足其约束”的取值后
        # 表达式仍可由其余事实满足，则该事实不阻断（典型为已成立的 or 分支）。
        blocking: set[str] = set()
        for name in missing_names:
            non_satisfying = self._non_satisfying_values(
                name, constraints.get(name, ()), negated=name in negated)
            if non_satisfying is None:
                blocking.add(name)
                continue
            avoidable = False
            for value in non_satisfying:
                trial = dict(facts)
                trial.update(completion)
                trial[name] = value
                if self._evaluator.eval_tree(tree, trial) == TRUE:
                    avoidable = True
                    break
            if not avoidable:
                blocking.add(name)
        return blocking

    def _collect_negated_names(self, tree: ast.AST) -> set[str]:
        """收集直接位于 Not 之下的裸名称（极性为负）。"""
        negated: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
                operand = node.operand
                if isinstance(operand, ast.Name):
                    negated.add(operand.id)
        return negated

    def _satisfying_completion(self, tree: ast.AST, facts: Mapping[str, Any],
                               witness_lists: Mapping[str, Sequence[Any]]
                               ) -> dict[str, Any] | None:
        """寻找一组让表达式成立的补证取值（按缺失事实做笛卡尔尝试，带短路）。"""
        names = tuple(witness_lists)
        def search(index: int, assigned: dict[str, Any]) -> dict[str, Any] | None:
            if index == len(names):
                trial = dict(facts)
                trial.update(assigned)
                return assigned if self._evaluator.eval_tree(tree, trial) == TRUE else None
            name = names[index]
            for value in witness_lists[name]:
                assigned[name] = value
                found = search(index + 1, assigned)
                if found is not None:
                    return dict(found)
            assigned.pop(name, None)
            return None
        return search(0, {})

    def _collect_constraints(self, tree: ast.AST) -> dict[str, tuple[ast.AST, ...]]:
        constraints: dict[str, list[ast.AST]] = defaultdict(list)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Compare):
                continue
            for side in [node.left, *node.comparators]:
                for name_node in ast.walk(side):
                    if isinstance(name_node, ast.Name):
                        constraints[name_node.id].append(node)
        return {key: tuple(value) for key, value in constraints.items()}

    def _witness_values(self, name: str,
                        comparisons: Sequence[ast.AST],
                        negated: bool = False) -> tuple[Any, ...]:
        """按缺失事实参与的比较 / 成员运算推断类型，给出可让条件成立的取值。"""
        values: list[Any] = []
        for node in comparisons:
            for op, left, right in _pairs(node):
                if not self._side_mentions(left, name) and not self._side_mentions(right, name):
                    continue
                name_on_left = self._side_mentions(left, name)
                constant_side = right if name_on_left else left
                if isinstance(op, (ast.In, ast.NotIn)):
                    container = _static_container(constant_side)
                    if container is not None and container:
                        if isinstance(op, ast.In):
                            values.extend(container)
                        else:
                            values.extend([f'__outside_{name}__', -1, None])
                    continue
                base = _static_scalar(constant_side)
                if base is None:
                    continue
                plain_side = left if name_on_left else right
                # 名称出现在算术表达式内时，按已知兄弟操作数推断可让条件成立的取值。
                if not _is_plain_name(plain_side, name):
                    arithmetic_value = self._arithmetic_witness(
                        plain_side, name, op, base, name_on_left)
                    if arithmetic_value is not None:
                        values.append(arithmetic_value)
                    else:
                        # 兄弟操作数同样缺失，无法反解：给数值候选供组合搜索。
                        values.extend([1, 1000, 10000])
                    continue
                # 统一成“name OP base”的方向再选证人，避免左右侧混淆。
                effective = op
                if not name_on_left:
                    effective = _flip_operator(op)
                if isinstance(effective, (ast.Eq, ast.LtE, ast.GtE)):
                    values.append(base)
                if isinstance(effective, ast.Lt):
                    values.append(base - 1 if isinstance(base, (int, float)) else base)
                if isinstance(effective, ast.Gt):
                    values.append(base + 1 if isinstance(base, (int, float)) else base)
                if isinstance(effective, ast.NotEq):
                    values.append(base + 1 if isinstance(base, (int, float)) else f'not_{base}')
        if not values:
            # 裸名称（布尔语境，含 not）或仅参与算术：按极性给出可让条件成立的值。
            if negated:
                values.extend([False, 0, ''])
            elif self._numeric_context(name, comparisons):
                values.extend([1, 1000, 10000])
            else:
                values.extend([True, 1, 'present'])
        return tuple(dict.fromkeys(values))

    def _numeric_context(self, name: str, comparisons: Sequence[ast.AST]) -> bool:
        for node in comparisons:
            for side in [node.left, *node.comparators]:
                if not self._side_mentions(side, name):
                    continue
                for sub in ast.walk(side):
                    if isinstance(sub, ast.BinOp) and isinstance(
                            sub.op, (ast.Add, ast.Sub, ast.Mult, ast.Div)):
                        return True
        return False

    @staticmethod
    def _side_mentions(side: ast.AST, name: str) -> bool:
        return any(isinstance(node, ast.Name) and node.id == name
                   for node in ast.walk(side))

    def _non_satisfying_values(self, name: str,
                               comparisons: Sequence[ast.AST],
                               negated: bool = False) -> tuple[Any, ...] | None:
        """给出让该名称所参与的原子条件不成立的取值；无法静态推断时返回 None。"""
        values: list[Any] = []
        for node in comparisons:
            for op, left, right in _pairs(node):
                name_on_left = self._side_mentions(left, name)
                name_on_right = self._side_mentions(right, name)
                if not name_on_left and not name_on_right:
                    continue
                constant_side = right if name_on_left else left
                if isinstance(op, (ast.In, ast.NotIn)):
                    container = _static_container(constant_side)
                    if container is None:
                        return None
                    outside = f'__outside_{name}__'
                    if isinstance(op, ast.In):
                        values.append(outside)
                    elif container:
                        values.append(container[0])
                    continue
                base = _static_scalar(constant_side)
                if base is None:
                    return None
                plain = _is_plain_name((left if name_on_left else right), name)
                if not plain:
                    # 算术语境无法可靠反解，保守标记为不可回避。
                    return None
                effective = op if name_on_left else _flip_operator(op)
                if isinstance(effective, ast.Eq):
                    values.append(base + 1 if isinstance(base, (int, float))
                                  else f'not_{base}')
                elif isinstance(effective, ast.NotEq):
                    values.append(base)
                elif isinstance(effective, ast.Lt):
                    values.append(base)
                elif isinstance(effective, ast.LtE):
                    values.append(base + 1 if isinstance(base, (int, float)) else base)
                elif isinstance(effective, ast.Gt):
                    values.append(base)
                elif isinstance(effective, ast.GtE):
                    values.append(base - 1 if isinstance(base, (int, float)) else base)
        if not values:
            # 裸名称：不成立即与极性相反的布尔取值。
            return (True, 1) if negated else (False, 0, '')
        return tuple(dict.fromkeys(values))

    def _arithmetic_witness(self, side: ast.AST, name: str,
                            op: ast.AST, base: Any, name_on_left: bool):
        """为算术语境（如 income - rent >= 2000）推断一个可让比较成立的取值。"""
        if not isinstance(side, ast.BinOp):
            return None
        binop = side
        left_mentions = self._side_mentions(binop.left, name)
        right_mentions = self._side_mentions(binop.right, name)
        sibling_node = binop.right if left_mentions else binop.left
        sibling = self._static_value(sibling_node)
        if sibling is None:
            return None
        # 先按比较方向得到“整体表达式需要达到的目标值”。
        if isinstance(op, (ast.Gt, ast.GtE)):
            target = base if isinstance(op, ast.GtE) else base + 1
        elif isinstance(op, (ast.Lt, ast.LtE)):
            target = base if isinstance(op, ast.LtE) else base - 1
        elif isinstance(op, ast.Eq):
            target = base
        else:
            return None
        if isinstance(binop.op, ast.Add):
            return target - sibling
        if isinstance(binop.op, ast.Sub):
            # name - sibling OP target  => name OP target + sibling
            # sibling - name OP target  => name = sibling - target
            return target + sibling if left_mentions else sibling - target
        if isinstance(binop.op, ast.Mult):
            if sibling == 0:
                return None
            return target / sibling
        return None

    def _static_value(self, node: ast.AST):
        """常量直接取值；已知名称取事实值；其余返回 None。"""
        if isinstance(node, ast.Constant):
            return node.value
        if isinstance(node, ast.Name):
            return self._current_facts.get(node.id) if node.id in self._current_facts else None
        return None

    def _potential_benefit(self, person: Mapping[str, Any], status: str):
        if status == INELIGIBLE:
            return None
        raw = person.get('amount')
        benefit = self.default_benefit if raw is None else decimal.Decimal(str(raw))
        if benefit is None:
            return None
        return benefit.quantize(decimal.Decimal('0.01'))

    def _undetermined(self, person_id, owner_id, group, facts, version, day,
                      person, explanations) -> PersonGapAnalysis:
        return PersonGapAnalysis(
            person_id=person_id, owner_id=owner_id, group=group,
            status=UNDETERMINED, applied_version=version,
            evaluated_on=day.isoformat() if day else None,
            known_facts=facts, missing_facts=(), blocking_facts=(),
            determined=False, explanations=tuple(explanations),
            benefit_unit=self.benefit_unit,
            potential_benefit=self._potential_benefit(person, UNDETERMINED),
            record_key=person.get('request_key'))

    def _build_report(self, people: Sequence[PersonGapAnalysis],
                      moment: dt.datetime) -> GapAnalysisReport:
        by_fact = self._summarize_fact_types(people)
        by_group = self._summarize_groups(people)
        budget = self._budget_bounds(people)
        totals = {
            'people': len(people),
            'eligible': sum(item.status == ELIGIBLE for item in people),
            'ineligible': sum(item.status == INELIGIBLE for item in people),
            'unknown': sum(item.status == UNDETERMINED for item in people),
            'determined': sum(item.determined for item in people),
            'needs_evidence': sum(not item.determined for item in people),
            'people_with_any_missing_fact': sum(bool(item.missing_facts) for item in people),
            'missing_fact_records': sum(len(item.missing_facts) for item in people),
            'blocking_fact_records': sum(len(item.blocking_facts) for item in people),
        }
        return GapAnalysisReport(
            generated_at=moment.isoformat(),
            people=list(people),
            by_fact_type=by_fact,
            by_group=by_group,
            budget=budget,
            unit_warnings=tuple(dict.fromkeys(self.unit_warnings)),
            version_warnings=tuple(self.version_warnings),
            totals=totals,
            disclaimer=DISCLAIMER,
        )

    def _summarize_fact_types(self, people: Sequence[PersonGapAnalysis]):
        rows: dict[str, dict[str, Any]] = {}
        for person in people:
            for gap in person.missing_facts:
                row = rows.setdefault(gap.fact, {
                    'fact': gap.fact,
                    'unit': gap.unit,
                    'missing_people': 0,
                    'blocking_people': 0,
                    'non_blocking_people': 0,
                    'verification_items': 0,
                    'versions': set(),
                    'people_ids': [],
                })
                row['missing_people'] += 1
                row['verification_items'] += 1
                row['versions'].update(gap.appears_in_versions)
                row['people_ids'].append(person.person_id)
                if gap.blocking:
                    row['blocking_people'] += 1
                else:
                    row['non_blocking_people'] += 1
        result = {}
        for fact in sorted(rows):
            row = rows[fact]
            row['versions'] = sorted(row['versions'])
            result[fact] = row
        return result

    def _summarize_groups(self, people: Sequence[PersonGapAnalysis]):
        groups: dict[str, list[PersonGapAnalysis]] = defaultdict(list)
        for person in people:
            groups[person.group].append(person)
        result = {}
        for group in sorted(groups):
            members = groups[group]
            result[group] = {
                'people': len(members),
                'eligible': sum(item.status == ELIGIBLE for item in members),
                'ineligible': sum(item.status == INELIGIBLE for item in members),
                'unknown': sum(item.status == UNDETERMINED for item in members),
                'needs_evidence': sum(not item.determined for item in members),
                'verification_items': sum(len(item.blocking_facts) for item in members),
            }
        return result

    def _budget_bounds(self, people: Sequence[PersonGapAnalysis]) -> BudgetBounds:
        # 每人至多一笔潜在补贴：先按人去重，再在两种极端世界之间求上下界。
        certain_eligible = [p for p in people if p.status == ELIGIBLE]
        undetermined = [p for p in people if p.status == UNDETERMINED]
        lower_amount = sum((p.potential_benefit or decimal.Decimal('0')
                            for p in certain_eligible), decimal.Decimal('0'))
        upper_amount = lower_amount + sum(
            (p.potential_benefit or decimal.Decimal('0') for p in undetermined),
            decimal.Decimal('0'))
        lower_count = len(certain_eligible)
        upper_count = lower_count + len(undetermined)
        capacity = self.capacity
        remaining = None
        free_after_worst_case = None
        at_risk = False
        max_accepted = None
        if capacity is not None:
            # 名义余量按容量与“确定合格”人数计算；待核人可能进一步占用该余量，
            # 故同时给出最坏情形（全部待核人合格）后的剩余容量。
            remaining = max(0, capacity - lower_count)
            max_accepted = min(capacity, upper_count)
            free_after_worst_case = max(0, capacity - upper_count)
            at_risk = upper_count > capacity
        per_person = None if self.default_benefit is None else str(
            self.default_benefit.quantize(decimal.Decimal('0.01')))
        return BudgetBounds(
            currency_unit=self.benefit_unit,
            benefit_per_person=per_person,
            lower_required=str(lower_amount.quantize(decimal.Decimal('0.01'))),
            upper_required=str(upper_amount.quantize(decimal.Decimal('0.01'))),
            reserve_recommended=str(upper_amount.quantize(decimal.Decimal('0.01'))),
            certain_eligible_count=lower_count,
            undetermined_count=len(undetermined),
            determined_ineligible_count=sum(p.status == INELIGIBLE for p in people),
            headcount_lower=lower_count,
            headcount_upper=upper_count,
            capacity=capacity,
            remaining_capacity=remaining,
            free_capacity_worst_case=free_after_worst_case,
            capacity_at_risk=at_risk,
            max_possible_accepted=max_accepted,
        )


def _as_date(value: Any) -> dt.date | None:
    if value is None or value == '':
        return None
    if isinstance(value, dt.datetime):
        return value.date()
    if isinstance(value, dt.date):
        return value
    return dt.date.fromisoformat(str(value))


def _pairs(compare: ast.Compare):
    sides = [compare.left, *compare.comparators]
    return tuple(zip(compare.ops, sides, sides[1:]))


def _static_scalar(node: ast.AST):
    if isinstance(node, ast.Constant):
        return node.value
    return None


def _static_container(node: ast.AST):
    if isinstance(node, (ast.List, ast.Tuple)):
        values = []
        for child in node.elts:
            if not isinstance(child, ast.Constant):
                return None
            values.append(child.value)
        return values
    return None


def _is_plain_name(node: ast.AST, name: str) -> bool:
    return isinstance(node, ast.Name) and node.id == name


def _flip_operator(op: ast.AST) -> ast.AST:
    """把 constant OP name 翻转为等价的 name flipped_op constant 方向。"""
    if isinstance(op, ast.Lt):
        return ast.Gt()
    if isinstance(op, ast.LtE):
        return ast.GtE()
    if isinstance(op, ast.Gt):
        return ast.Lt()
    if isinstance(op, ast.GtE):
        return ast.LtE()
    return op


def analyze_fixture(fixture: Mapping[str, Any],
                    now: dt.datetime | None = None) -> GapAnalysisReport:
    """便捷入口：直接对验收夹具结构做缺口分析。"""
    analyzer = GapAnalyzer.from_context(fixture.get('context', {}))
    return analyzer.analyze_people(fixture.get('items', ()), now=now)
