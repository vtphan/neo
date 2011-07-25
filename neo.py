import os
import re
import sys
import json
import http
import hmac
import string
import random
import sqlite3
import mimetypes
import threading
import traceback
from html import escape
from http import cookies
from functools import wraps
from cgi import FieldStorage
from random import choice, randint
from wsgiref.headers import Headers
from collections import OrderedDict, namedtuple
from contextlib import ContextDecorator
from time import time, strptime, strftime, gmtime
from inspect import getargspec, getmembers, isclass
from urllib.parse import parse_qs, urlencode, quote_plus
from multiprocessing import Process, Queue, Manager, current_process

#-------------------- GLOBALS--------------------------------------------------
SECRET = b'\x18N\xa5\\\xf1@\xc0\xc5\xf1\x08\x95\xbbJy\xd8cX\x03:Y\xfd\x0e\\b'
DATA = 'Data'
if not os.path.isdir(os.path.join(os.getcwd(), DATA)):
    os.mkdir(os.path.join(os.getcwd(), DATA))
APP_DIR = os.path.join(DATA,'{}')
LAYOUT_DIR = os.path.join(APP_DIR,'layout')
BASE_LAYOUT_DIR = os.path.join(APP_DIR,'layout','__parent__')
DOWNLOAD_DIR = os.path.join(APP_DIR,'download')
STATIC_DIR = os.path.join(APP_DIR,'static')
LAYOUT = os.path.join(LAYOUT_DIR,'{}.html')

Info = namedtuple('Info', ['app_d','layout_d','base_layout_d','download_d',
                           'static_d', 'route'])

def flash(m): cookie.set('_message_',m.encode(),expires=0)

http_status = {'200':'200 OK', '303':'303 See Other', '304':'304 Not Modified',
               '404':'404 Not Found', '500':'500 Internal Server Error'}
#-------------------- REQUEST, RESPONSE ---------------------------------------
class Request(threading.local):
    def __init__(self): self.setup({})

    def setup(self, env):
        self.env = env
        self.ip = env.get('REMOTE_ADDR', '')
        self.method = env.get('REQUEST_METHOD','')
        self.qs = self.query_string()
        if 'HTTP_HOST' in env: self.httphost = env['HTTP_HOST']
        elif 'SERVER_NAME' in env and 'SERVER_PORT' in env:
            if env['SERVER_PORT'] != '80':
                self.httphost = env['SERVER_NAME'] + ':' + env['SERVER_PORT']
            else: self.httphost = env['SERVER_NAME']
        else: self.httphost = ''
        self.url_scheme = env.get('wsgi.url_scheme', '')
        self.url_root = self.url_scheme + '://' + self.httphost
        
    def query_string(self):
        if self.method == 'POST':
            self.env['QUERY_STRING'] = ''
            form = FieldStorage(fp=self.env['wsgi.input'], environ=self.env)
            qs = { key:self._get_field(form,key) for key in form }
            return { k:v for k,v in qs.items() if v }
        else:
            if 'QUERY_STRING' not in self.env: self.env['QUERY_STRING'] = ''
            return { k:escape(v[0]) if len(v)==1 else [escape(i) for i in v]
                     for k,v in parse_qs(self.env['QUERY_STRING']).items() }

    def _get_field(self, form, key):
        if type(form[key]) == list:
            return [ escape(i) for i in form.getlist(key) ]
        elif form[key].type=='text/plain' or not form[key].type:
            return escape(form.getfirst(key))
        elif form[key].file: 
            if not form[key].filename: return None
            name, abs_name = self._rand_filename(form[key].filename)
            with open(abs_name,'wb+') as f:
                while True:
                    cur = form[key].file.read(4096)
                    if not cur: break
                    f.write(cur)
            return {'path':abs_name, 'name':name}
        return form.getfirst(key)

    def _rand_filename(self, name):
        symbols = string.ascii_lowercase + string.digits
        while True:
            rstr = ''.join(random.choice(symbols) for i in range(10))
            fname = os.path.join(DOWNLOAD_DIR,rstr+'_'+name)
            if not os.path.isfile(fname): return rstr+'_'+name, fname

class Response(threading.local):
    def setup(self):
        self.status = http_status['200']
        self.headers = Headers([('Content-type','text/html; charset=UTF-8')])
        self.out = b''

    def download(self, dir, args, cd=False):
        ims = request.env.get('HTTP_IF_MODIFIED_SINCE', '')
        file = os.path.join(dir, *args)
        if not os.access(file, os.R_OK):
            self.error(mesg='File not found',raise_exc=True)
        mimetype, encoding = mimetypes.guess_type(file)
        if mimetype: self.headers.add_header('Content-Type',mimetype)
        if encoding: self.headers.add_header('Content-Encoding',encoding)
        if cd:
            self.headers.add_header('Content-Disposition','attachment',filename=args[-1])
        stats = os.stat(file)
        self.headers.add_header('Content-Length', str(stats.st_size))
        time_fmt = "%a, %d %b %Y %H:%M:%S GMT"
        last_modified = strftime(time_fmt, gmtime(stats.st_mtime))
        self.headers.add_header('Last-Modified', last_modified)

        if ims: ims = strptime(ims.split(";")[0].strip(), time_fmt)
        else: ims = None
        if ims is not None and ims >= gmtime(stats.st_mtime-2):
            date = strftime(time_fmt, gmtime())
            self.headers.add_header('Date', date)
            self.status = http_status['304']
        elif request.method == 'HEAD': self.out = ''
        else: self.out = open(file,'rb').read()

    def error(self, mesg='', status='404', raise_exc=True):
        self.status = http_status[status]
        self.out = mesg
        self.headers = Headers([('Content-type','text/plain')])
        if raise_exc: raise Exception('ResponseError NotFound')

    def output(self):
        self.headers.add_header('Content-Length', str(len(self.out)))
        if type(self.out)==str: return self.out.encode('utf-8')
        return self.out

#-------------------- COOKIE, SESSION -----------------------------------------
class Cookie(threading.local):
    def __init__(self):
        self.cookie = http.cookies.SimpleCookie()
        
    def setup(self, env, secret_key):
        self.secret_key = secret_key
        self.cookie.clear()
        self.ip = env.get('REMOTE_ADDR', '')
        self.message = ''
        if env and 'HTTP_COOKIE' in env:
            self.cookie.load(env['HTTP_COOKIE'])
            if '_message_' in self.cookie:
                self.message = self.cookie['_message_'].value[2:-1]

    def teardown(self):
        if self.message: self.set('_message_', '', expires=-3600*24)

    def get(self, key):
        if key not in self.cookie: print('unknown cookie:',key); return ''
        value = self.cookie[key].value.split(':neo_sign:')
        if len(value) == 1: return value[0]
        if not self.ip: return ''
        expires, ip, client_sig = value[1].split('|')
        value = value[0]
        v = value+':neo_sign:'+expires+'|'+ip+'|'
        sig = hmac.new(self.secret_key, v.encode()).hexdigest()
        if sig != client_sig: print('cookie tampered',key); return ''
        if expires and float(expires) < time():
            print('cookie expired',key); return ''
        if ip != self.ip: print('ip address unmatched',key); return ''
        return value

    def _set(self,key,value,expires=2592000,path='/',httponly=False,secure=False):
        self.cookie[key] = value
        self.cookie[key]['path'] = path
        if expires: self.cookie[key]['expires'] = expires
        if httponly: self.cookie[key]['httponly'] = True
        if secure: self.cookie[key]['secure'] = True
        self.cookie[key].modified = True

    def set(self,key,value,expires=2592000,path='/',secure=False,httponly=False,signed=False):
        if not signed:
            self._set(key,value,expires,path,secure)
        else:
            exp = str(expires+time()) if expires else ''
            value = str(value)+':neo_sign:'+exp+'|'+self.ip+'|'
            value += hmac.new(self.secret_key, value.encode()).hexdigest()
            self._set(key,value,expires,path,secure)

    def build_headers(self, headers):
        for k,v in self.cookie.items():
            if hasattr(v, 'modified'):
                headers.add_header('Set-Cookie',v.output(header=''))


class Session(threading.local):
    def add(self, key, value):
        cookie.set(key, value, expires=0, signed='session')

    def get(self, key):
        return cookie.get(key)

    def pop(self, key):
        cookie.set(key, 'expired', expires=-3600*24, signed=True)

#-------------------- DATABASE ------------------------------------------------

# w = Where('id > ? and name!=?', 5, 'john')
# w & ('id<? and age>?', 10, 15)
class Where:
    def __init__(self, query, *args):
        self.query = [query]
        self.args = list(args)

    def __and__(self, c):
        if type(c) == tuple:
            self.args.extend(c[1:])
            c = c[0]
        self.query[-1] = self.query[-1]+' and '+c

    def __or__(self, c):
        if type(c) == tuple:
            self.args.extend(c[1:])
            c = c[0]
        self.query.append(c)

    def __call__(self):
        if len(self.query) == 1: return (' where '+self.query[0], self.args)
        query = ' where '+' or '.join('('+i+')' for i in self.query)
        return query,self.args


class SQLite(ContextDecorator, threading.local):
    def __init__(self, db_name):
        self.db_name = db_name

    def __enter__(self):
        self.conn = sqlite3.connect(self.db_name)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type: print('Error', exc_type, exc_val)
        self.conn.close()
        return False

    def close(self):
        self.conn.close()

    def __call__(self, query, *others):
        if others:
            if type(others[0]) == Where: w,args = others[0]()
            else: w,args = '', others[0] if type(others[0])==tuple else others
        else: w, args = '', []
        query = query.format(where=w) if '{where}' in query else query+w
        try:
            with self.conn:
                return [tuple(i) for i in self.conn.execute(query, args)]
        except: print('SQLite error')

#-------------------- MARKUP --------------------------------------------------

class Markup:
    def __init__(self):
        self.tok = {'-': ('-','<li>','</li>','\n<ul>','</ul>\n'),
                    '+': ('+','<li>','</li>','\n<ol>','</ol>\n'),
                    ':': (':','','','\n<blockquote>','</blockquote>\n'),
                    'def': ('','','','\n<p>','</p>\n') }
        self.inline_pat = re.compile(
        '''[\n\r]#\s(.+)|[\n\r]##\s(.+)|[\n\r]###\s(.+)|\*\*(.+?)\*\*|\*(.+?)\*|\
\[\[([^\s\]]+)\s(left|right|middle)\s(\d+px)\]\]|\
\[\[([^\]]+)\s([^\s\]]+)\]\]''')
        self.template = [
            '<h1>{}</h1>','<h2>{}</h2>','<h3>{}</h3>','<b>{}</b>','<i>{}</i>',
            '<img src="{}" align="{}" width="{}"/>', '<a href="{}">{}</a>'
            ]

    def parse_item(self, lines, token):
        if not lines or not lines[0].strip() or (token and lines[0][0]==token):
            return ''
        return lines.pop(0) + self.parse_item(lines, token)

    # token: '-', '+', ':', '' (paragraph)
    def parse_block(self, lines, token, prefix, suffix):
        if not lines or not lines[0].strip() or (token and lines[0][0]!=token):
            return ''
        line = lines.pop(0)
        first = line if not token else line[1:]
        item = first + self.parse_item(lines, token)
        return prefix+item+suffix + self.parse_block(lines,token,prefix,suffix)

    def parse(self, lines, output, is_last_line_empty):
        if not lines: return output
        line = lines[0].strip()
        if is_last_line_empty and line:
            i = self.tok[line[0]] if line[0] in self.tok else self.tok['def']
            block = self.parse_block(lines, i[0], i[1], i[2])
            output.append(i[3] + block + i[4])
            is_last_line_empty = False
        else:
            is_last_line_empty = (line == '')
            output.append(lines.pop(0))
        return self.parse(lines, output, is_last_line_empty)

    def rep(self, match):
        if match.groups():
            m = [(i,j) for i,j in enumerate(match.groups()) if j]
            if len(m)==1: return self.template[m[0][0]].format(m[0][1])
            if len(m)==2: return self.template[6].format(m[1][1], m[0][1])
            return self.template[5].format(m[0][1],m[1][1],m[2][1])

    def __call__(self, s , esc=False):
        if not s: return ''
        if esc: s = escape(s)
        s = re.sub(self.inline_pat, self.rep, s, re.DOTALL).split('\n')
        return ''.join( self.parse(s, [], False) )

markup = Markup()
#-------------------- TEMPLATE ------------------------------------------------

class SimpleTemplate:
    def __init__(self, filename, parent_dir):
        self.filename = filename
        self.parent_file = ''
        self.parent_vars = []
        self.tmpl = OrderedDict()
        with open(self.filename) as fp: input = fp.read().split('\n')
        match = re.match('%use\s+([\w\.]+)$', input[0])
        if match:
            self.parent_file = os.path.join(parent_dir, match.groups()[0])
            with open(self.parent_file) as f: parent_input = f.read()
            self.parent_vars = re.findall('{([a-zA-Z_]\w*)}', parent_input)
            parent_input = parent_input.split('\n')
            saved = self.parse(['_parent_=[]\n'],'','','_parent_',parent_input)
            input.pop(0)
        self.tmpl['_self_'] = self.parse(['_self_=[]\n'],'','','_self_',input)
        for v in self.parent_vars:
            if v!='end' and v not in self.tmpl: self.tmpl[v] = ''
        if self.parent_file: self.tmpl['_parent_'] = saved

    def render(self, context):
        for var, t in self.tmpl.items():
            if t or var not in context:
                lc = {}
                exec(t, context, lc)
                context[var] = lc[var] if var in lc else ''
                if self.parent_file and var=='_self_': context.update(lc)
        return context['_parent_'] if self.parent_file else context['_self_']

    '''
    lines: accumulated list of codes; block: current (str) block of texts
    '''
    def parse(self, lines, block, indent, context, input):
        if not input or input[0].strip() == '{end}':
            if input: input.pop(0)
            block = self._save_block(block, lines, indent, context)
            if not indent: 
                lines.append(context+"= ''.join("+context+")\n")
                return compile('\n'.join(lines), '<string>', 'exec')
            return '\n'.join(lines)
        spaces = re.match('(\s*)', input[0]).groups()[0]
        line = input.pop(0).strip()
        v, expr = self._statement(line)
        if v:
            block = self._save_block(block, lines, indent, context)
            if v in ['for','if']:
                new_block = self.parse([],'',indent+'\t',context,input)
                lines.append(indent+line[1:-1]+'\n'+new_block)
            elif v in ['elif','else']: lines.append(indent[1:]+line[1:-1])
            elif expr: lines.append(indent+line[1:-1])
            else: self.tmpl[v] = self.parse([v+'=[]\n'],'','',v,input)
        elif not self._is_comment(line):
            expr=[i for i in re.findall('({[^{}]+})',line) if self._is_expr(i)]
            for ex in set(expr):
                block = self._save_block(block, lines, indent, context)
                u = self._new_variable()
                lines.append( indent + u+'='+ex[1:-1] )
                line = line.replace(ex, '{'+u+'}')
            if line: block += spaces + line.replace("'", "\\'") + '\n'
        return self.parse(lines,block,indent,context,input)

    def _new_variable(self):
        s = ''.join(choice(string.ascii_letters) for i in range(7))
        return s if s not in self.tmpl else self._new_variable()

    def _save_block(self, block, lines, indent, context):
        def reformat(expr):
            vars = re.findall('''{([a-zA-Z_]\w*)}''', expr)
            if not vars: return ".append('''"+expr+"''')"
            args = ','.join(i+'='+i for i in set(vars))
            return ".append('''"+expr+"'''.format("+args+"))"
        if block: lines.append(indent+context+reformat(block))
        return ''

    def _statement(self, line):
        m = re.match('{([a-zA-Z_]\w*)(\s*=\s*)?(.*)}$', line)
        if not m or not self._is_code(line): return None,None
        m = m.groups()
        if m[0] in ['for','if','elif','else']: return m[0],None
        return (m[0],m[2]) if m[1] else (None,None)

    def _is_comment(self, line):
        return line.startswith('{#') and line.endswith('#}')

    def _is_code(self, line): 
        if line.startswith('{ ') or line.endswith(' }'): return False
        return len(line)>1 and line.startswith('{') and line.endswith('}')

    def _is_variable(self, line): return re.match('{[a-zA-Z_]\w*}',line)
    
    def _is_expr(self, line):
        return self._is_code(line) and not self._is_variable(line)


#-------------------- APP ----------------------------------------------------
class App(object):
    info = {}
    
    def __new__(cls, app_name, db_name):
        if app_name not in App.info: App.info[app_name] = object.__new__(cls)
        return App.info[app_name]
        
    def __init__(self, app_name, db_name):
        if not hasattr(self, 'name'):
            self.name = app_name
            self.app_d = self.create_dir(APP_DIR)
            self.db = SQLite( os.path.join(self.app_d, db_name) )
            self.id = {'download':'download','static':'static', '000':'000'}
            self.route = {}
            self.internal = {}
            self._check()
            App.info[app_name] = self
 
    @classmethod
    def print(self):
        for n,a in App.info.items():
            print(a.name,'\n\t',a.layout_d,'\n\t',a.download_d,'\n\t',a.static_d)
            print('\tid:',a.id,'\n\tinternal:',a.internal,'\n\troute:',a.route)
    
    def __str__(self): return 'App:'+self.name
    
    def create_dir(self, dir):
        if not os.path.isdir(dir.format(self.name)):
            os.mkdir(dir.format(self.name))
        return dir.format(self.name)
            
    def _check(self):
        self.app_d = self.create_dir(APP_DIR)
        self.layout_d = self.create_dir(LAYOUT_DIR)
        self.base_layout_d = self.create_dir(BASE_LAYOUT_DIR)
        self.download_d = self.create_dir(DOWNLOAD_DIR)
        self.static_d = self.create_dir(STATIC_DIR)
    
    def quote(self, s, safe=''): return quote_plus(s.encode(), safe)

    def redirect(self, func, *args, **kw):
        if '_message' in kw: flash(kw['_message'])
        if func.startswith('http:'): path=func
        else: path = self.url(func, *args)
        if 't' in kw:
            response.headers.add_header('Refresh', str(kw['t']), url=path)
        response.out, response.status = '', http_status['303']
        response.headers.add_header('Location', path)
        raise Exception('NeoRedirect')
    
    def url(self, func, *args):
        if func not in self.id: return 'unknown_controller'
        else: id = self.id[func] if func != '/' else ''
        path = '/'+'/'.join(str(i) for i in args) if args else ''
        if len(App.info)==1: return request.url_root +'/'+ id + path
        else: return request.url_root+'/'+ self.name +'/'+id+path
            
    def dispatch(self, controller, u_args, qs, json_out):
        def build_context(context=None):
            if type(context)==str: return context
            new_context = dict(url=self.url, quote=self.quote, escape=escape,
                               markup=markup, message=cookie.message)
            new_context.update(self.internal)
            if context: new_context.update(context)
            return new_context

        con, tmpl = self.route[controller]
        f = getattr(con, request.method.lower())
        args = getargspec(f).args
        if len(u_args) > len(args): response.error('too many parameters','500')
        def_args = getargspec(f).defaults
        nondef_args = args[:-len(def_args)] if def_args else args
        params = {args[i]:v for i,v in enumerate(u_args)}
        params.update({ k:v for k,v in qs.items() if k in args })
        missing_args = [k for k in nondef_args if k not in params]
        try:
            if missing_args:
                if 'HTTP_REFERER' in request.env:
                    flash(', '.join(missing_args)+' missing')
                    self.redirect(request.env['HTTP_REFERER'])
                else: response.error(', '.join(missing_args)+' missing', '500')
            else:
                ret = f(**params) if params else f()
                if json_out: response.out = json.dumps(ret)
                else:
                    cxt = build_context(ret)
                    response.out = tmpl.render(cxt) if type(cxt)==dict else cxt 
        except Exception as err:
            if err.args and err.args[0] == 'NeoRedirect': return
            else: response.error(traceback.format_exc(), '500', False)

    def expose(self, *controllers):
        def internal_deco(f, tmpl):
            @wraps(f)
            def my_deco(*args, **kwargs):
                cxt = dict(url=self.url,markup=markup,escape=escape,quote=self.quote)
                context = f(*args, **kwargs)
                if type(context) == str: return(context)
                cxt.update(context)
                return tmpl.render(cxt)
            return my_deco
        
        for c in controllers:
            tmpl_file = LAYOUT.format(self.name, c.__name__)
            if not os.path.isfile(tmpl_file): open(tmpl_file,'w').close()
            tmpl = SimpleTemplate(tmpl_file, self.base_layout_d)
            if hasattr(c, 'get') or hasattr(c, 'post'):
                self.id[c.__name__] = c._id_.strip('/') if hasattr(c,'_id_') else c.__name__
                self.route[self.id[c.__name__]] = (c, tmpl)
            if hasattr(c, 'internal'):
                cxt = dict(url=self.url, markup=markup, escape=escape,
                           quote=self.quote)
                self.internal[c.__name__] = internal_deco(c.internal, tmpl)

    def lookup_queue(self, id):
        delay = 4000
        result = task_queue.get(id)
        if result == '_NotFound_':
            response.out = '<html><head><script type="text/javascript">window.onload = function(){ setTimeout(function(){ window.location.reload(); }, '+str(delay)+') }</script></head></html>'
        else:
            response.out = '<html><head><script type="text/javascript">window.parent.document.getElementById("{}").innerHTML={}</script></head></html>'.format(id, result)
            
    def queue(self, f, *args):
        id = task_queue.add(f, args)
        u = self.url('000', id)
        return '<div id="{}"></div><iframe src="{}" width="0" height="0" frameborder="0"></iframe>'.format(id, self.url('000', id))

#-------------------- NEO APP ------------------------------------------------

class NeoApp:
    @classmethod
    def setup(cls, apps):
        for app_name in apps: mod = __import__(app_name)
        
    def before_dispatch(self, env):
        cookie.setup(env, SECRET)
        request.setup(env)
        response.setup()

    def after_dispatch(self):
        cookie.teardown()
        cookie.build_headers( response.headers )       

    def lookup(self):
        part = self.path.strip('/').split('/')
        app =  App.info[part[0]] if part[0] in App.info else None
        if not app: response.error('unknown app: '+part[0])
        controller = part[1] if len(part)>1 else ''
        if controller in ['download','static','000']: return (app,part[1],part[2:])
        if controller not in app.route:
            response.error('unknown controller: '+controller)
        con = app.route[controller][0]
        if not hasattr(con,request.method.lower()):
            response.error('No '+request.method+' for '+con.__name__)
        return (app, controller, part[2:])
        
    def __init__(self, env, start_response):
        self.start = start_response
        if env['PATH_INFO'].endswith('.json'):
            self.path, self.json = env['PATH_INFO'][:-5], True
        else: self.path, self.json = env['PATH_INFO'], False
        if len(App.info)==1: self.path = list(App.info.keys())[0]+self.path
        self.before_dispatch(env)

    def __iter__(self):
        try:
            app, con, args = self.lookup()
            if con in ['download', 'static']:
                dir = app.static_d if con=='static' else app.download_dir
                response.download(dir, args, 'save_as' in args)
            elif con == '000': app.lookup_queue(args[0])
            else: app.dispatch(con, args, request.qs, self.json)
        except Exception as err:
            if err.args and err.args[0] != 'ResponseError NotFound':
                response.error(traceback.format_exc(), '500', False)
        self.after_dispatch()
        self.start(response.status, response.headers.items())
        yield response.output()

    
#-------------------- TASK QUEUE ---------------------------------------------
class TaskQueue:
    N = 4
    symb = string.ascii_letters + string.digits
    
    def __init__(self):
        self.tasks = Queue()
        self.done = Queue()
        self.results = {}
        self.processes = []
        for i in range(TaskQueue.N):
            self.processes.append(Process(target=self.run_tasks))
            self.processes[-1].start()
        threading.Thread(target=self.collect_results).start()

    def add(self, f, args):
        id = ''.join(random.choice(TaskQueue.symb) for i in range(15))
        self.tasks.put((id, f,args))
        return id

    def get(self, id):
        return self.results.pop(id, '_NotFound_')
            
    def run_tasks(self):
        for id, func, args in iter(self.tasks.get, 'STOP'):
            result = func(*args)
            self.done.put((id,result))

    def collect_results(self):
        for id, r in iter(self.done.get, 'STOP'):
            self.results[id] = r
            #print('Collect_result:', current_process().name, id, r)

#-------------------- inter-module variables ---------------------------------

request = None
response = None
cookie = None
session = None
task_queue = None

#-------------------- MAIN ---------------------------------------------------
if __name__ == '__main__':
    import argparse
    from wsgiref.simple_server import make_server

    parser = argparse.ArgumentParser()
    parser.add_argument('-ip',default='127.0.0.1')
    parser.add_argument('-port',type=int,default='4321')
    parser.add_argument('apps',nargs='+',help='apps names')
    args = parser.parse_args()
    neo = __import__('neo')
    App = neo.App
    request = neo.request = Request()
    response = neo.response = Response()
    cookie = neo.cookie = Cookie()
    session = neo.session = Session()
    task_queue = neo.task_queue = TaskQueue()
    flash = neo.flash
    NeoApp.setup(args.apps)
#    App.print()
    print("Http serving on host",args.ip,"at port",args.port)
    try:
        make_server(args.ip,args.port,NeoApp).serve_forever()
    except KeyboardInterrupt:
        for p_t in task_queue.processes: p_t.terminate()
        print("\nexiting...")

