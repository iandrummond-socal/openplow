import importlib.util, os
s = importlib.util.spec_from_file_location('files', 'src/files.py')
m = importlib.util.module_from_spec(s); s.loader.exec_module(m)
real = os.path.normpath(os.path.join(m.BASE, '../../etc/passwd'))
assert not real.startswith(m.BASE), real
print('TRAVERSAL', real)
