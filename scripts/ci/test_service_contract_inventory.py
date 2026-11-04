"""Tests only the static census tool, never any Core/Guest runtime."""
from pathlib import Path
import tempfile,unittest
import service_contract_inventory as tool
class StaticInventoryTests(unittest.TestCase):
 def fixture(self,root,text):
  p=root/'main.go';p.write_text(text);return tool.generate(root)
 def test_comments_strings_methods_and_multiline_routes(self):
  with tempfile.TemporaryDirectory() as d:
   root=Path(d)
   result=self.fixture(root,'''package main
// mux.HandleFunc("GET /fake-comment", h)
var text = `mux.HandleFunc("GET /fake-string", h)`
func (s *Server) EmitEvent(ctx C, event E) error { return nil }
func real() {
 mux.HandleFunc("POST /actual", wrap(permission, h))
 mux.Handle("GET /nested", wrapper(
  http.HandlerFunc(handler)))
 repository.EmitEvent(ctx, tx, Request{Type: "manifest.created"})
 req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+path, nil)
}
''')
   self.assertEqual(len(result['http-routes']),2)
   self.assertEqual([r['pattern_expression'] for r in result['http-routes']],['"POST /actual"','"GET /nested"'])
   self.assertEqual(len(result['event-emissions']),1)
   self.assertEqual(result['event-emissions'][0]['type_expressions'],['"manifest.created"'])
   self.assertEqual(result['event-emissions'][0]['function'],'real')
   self.assertEqual(len(result['http-egress']),1)
 def test_build_constraints_and_compiled_docs_are_kept(self):
  with tempfile.TemporaryDirectory() as d:
   root=Path(d);(root/'docs/contracts').mkdir(parents=True);(root/'docs/contracts/validator.go').write_text('package contracts\n')
   (root/'scripts').mkdir();(root/'scripts/ignored.go').write_text('package main\n')
   result=self.fixture(root,'//go:build linux && nativequalification\npackage main\n')
   self.assertEqual(result['sources']['main.go']['build_constraint'],'linux && nativequalification')
   self.assertIn('docs/contracts/validator.go',result['sources']);self.assertNotIn('scripts/ignored.go',result['sources'])
 def test_shipped_commands_only_and_operation_edges(self):
  with tempfile.TemporaryDirectory() as d:
   root=Path(d)
   for name in ('goose','bootstrap','bootstrap-admin','development','ci'):
    p=root/'scripts'/name/'main.go';p.parent.mkdir(parents=True);p.write_text('package main\nfunc main(){ db,err:=psql.Open(); tx,err:=db.BeginTx(ctx,nil); tx.Commit() }\n')
   result=self.fixture(root,'package main\n')
   for name in tool.PRODUCTION_COMMANDS:self.assertIn('scripts/'+name+'/main.go',result['sources'])
   self.assertNotIn('scripts/development/main.go',result['sources']);self.assertNotIn('scripts/ci/main.go',result['sources'])
   self.assertEqual(len(result['production-command-operations']),9)
   self.assertEqual(set(x['command'] for x in result['production-command-operations']),set(tool.PRODUCTION_COMMANDS))
 def test_path_selection_has_exact_script_whitelist(self):
  cases={'scripts/goose/main.go':True,'scripts/bootstrap/main.go':True,'scripts/bootstrap-admin/nested/source.go':True,'scripts/goose_test/main.go':False,'scripts/goose/main_test.go':False,'scripts/other.go':False,'lib/scripts/goose/main.go':False,'scripts/goose/vendor/x.go':False,'docs/contracts/validator.go':True}
  for path,want in cases.items():self.assertEqual(tool.source_path(path),want,path)
 def test_indirect_source_is_refused(self):
  with tempfile.TemporaryDirectory() as d:
   root=Path(d);(root/'outside.txt').write_text('package main\n');(root/'main.go').symlink_to(root/'outside.txt')
   with self.assertRaises(ValueError):tool.generate(root)
if __name__=='__main__':unittest.main()
