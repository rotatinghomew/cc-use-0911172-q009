青年人才安居就业政策资格模拟与差异解释器
测试：python3 -m unittest discover -s tests -v
构建：python3 -m compileall -q policy_sandbox tests
验收：python3 -m policy_sandbox --database /tmp/policy_sandbox.sqlite3 run --fixture fixtures/acceptance.json --output /tmp/policy_sandbox-output.json
单测：python3 -m unittest tests.test_domain -v
资料缺口分析（三值逻辑，仅供补证优先级与预算预留，不改变正式资格）：
python3 -m policy_sandbox --database /tmp/gap.sqlite3 gap-analysis --fixture fixtures/gap_analysis.json --output /tmp/gap-output.json
缺口分析单测：python3 -m unittest tests.test_gap_analysis tests.test_gap_cli -v
