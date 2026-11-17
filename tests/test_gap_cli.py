import json
import tempfile
import unittest
from pathlib import Path

from policy_sandbox.cli import main


class GapAnalysisCliTests(unittest.TestCase):
    def test_gap_analysis_subcommand_writes_report(self):
        fixture = {
            'context': {
                'expression': "age >= 18 and degree in ['master','doctor']",
                'benefit': '1200',
                'capacity': 10,
                'three_valued': True,
                'units': {'age': 'years', 'benefit': 'CNY'},
            },
            'items': [
                {'id': 'a', 'facts': {'age': 25, 'degree': 'master'}},
                {'id': 'b', 'facts': {'age': 25}},
            ],
        }
        with tempfile.TemporaryDirectory() as directory:
            fixture_path = Path(directory) / 'fixture.json'
            output_path = Path(directory) / 'gap.json'
            db_path = Path(directory) / 'db.sqlite3'
            fixture_path.write_text(json.dumps(fixture), encoding='utf-8')
            code = main(['--database', str(db_path), 'gap-analysis',
                         '--fixture', str(fixture_path),
                         '--output', str(output_path)])
            self.assertEqual(code, 0)
            payload = json.loads(output_path.read_text(encoding='utf-8'))
            report = payload['gap_analysis']
            self.assertEqual(report['totals']['eligible'], 1)
            self.assertEqual(report['totals']['unknown'], 1)
            self.assertEqual(report['budget']['upper_required'], '2400.00')
            self.assertIn('disclaimer', report)


if __name__ == '__main__':
    unittest.main()
