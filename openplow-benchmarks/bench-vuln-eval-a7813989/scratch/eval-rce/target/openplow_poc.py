import importlib.util
s = importlib.util.spec_from_file_location('app', 'src/app.py')
m = importlib.util.module_from_spec(s); s.loader.exec_module(m)
print('PWNED', m.handler('6*7'))
