"""Existing Owned-job companion census; declared mock transport, no API/Native."""
import collections,json,os
from pathlib import Path
import subprocess,sys,unittest
HERE=Path(__file__).resolve().parent
OUT=Path(os.environ['GUARDIAN_CI_EVIDENCE'])/'cleanup94-client'


def flatten(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from flatten(item)
        else:
            yield item

class Outcomes(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.runs, self.passes = [], []

    def startTest(self, test):
        self.runs.append(test.id())
        super().startTest(test)

    def addSuccess(self, test):
        self.passes.append(test.id())
        super().addSuccess(test)

def main():
    OUT.mkdir(parents=True,exist_ok=True)
    actual=subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip()
    if actual!=os.environ['SOURCE_COMMIT']or subprocess.check_output(['git','status','--porcelain','--untracked-files=all']):
        raise RuntimeError('exact clean Source before client fixture import')
    expected=json.loads((HERE/'EXPECTED-CLIENT-TESTS.json').read_bytes())
    if type(expected)is not list or len(expected)!=8 or len(set(expected))!=8:
        raise RuntimeError('closed eight M94 client fixture methods required')
    suite=unittest.defaultTestLoader.discover(str(HERE),pattern='test_m94_cleanup_client.py')
    actual_ids=[test.id()for test in flatten(suite)]
    if collections.Counter(actual_ids)!=collections.Counter(expected):
        (OUT/'CENSUS-REFUSAL.PUBLIC.json').write_text(json.dumps({'expected':expected,'actual':actual_ids,'discovery_errors':list(unittest.defaultTestLoader.errors),'success':False},indent=2)+'\n')
        raise RuntimeError('client Source test discovery differs from reviewed roster')
    result=unittest.TextTestRunner(verbosity=2,resultclass=Outcomes).run(suite)
    clean=(subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip()==actual and not subprocess.check_output(['git','status','--porcelain','--untracked-files=all']))
    success=(result.wasSuccessful()and not result.skipped and not result.expectedFailures and not result.unexpectedSuccesses and result.testsRun==8 and collections.Counter(result.runs)==collections.Counter(expected)and collections.Counter(result.passes)==collections.Counter(expected)and clean)
    value={'schema':'failed_unwitnessed_expansion_cleanup_client_Source_census_v1','source_commit':actual,'success':bool(success),'expected':expected,'executed':result.runs,'passed':result.passes,'failures':[t.id()for t,_ in result.failures],'errors':[t.id()for t,_ in result.errors],'skipped':[t.id()for t,_ in result.skipped],'tests_run':result.testsRun,'exact_clean_source_before_and_after':clean,'declared_HTTP_and_FS_fixtures_only':True,'authentication_performed':False,'API_calls':0,'Native_or_provider_execution':False,'production_authority':False}
    (OUT/'CENSUS.PUBLIC.json').write_text(json.dumps(value,indent=2)+'\n')
    print(json.dumps({'source_commit':actual,'tests_run':result.testsRun,'success':bool(success),'production_authority':False}))
    return 0 if success else 1
if __name__=='__main__':sys.exit(main())
