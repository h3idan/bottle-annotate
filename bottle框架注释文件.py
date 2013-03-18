# coding: utf-8
"""
Bottle is a fast and simple mirco-framework for small web-applications. It
offers request dispatching (Routes) with url parameter support, Templates,
key/value Databases, a build-in HTTP Server? and adapters for many third party
WSGI/HTTP-server and template engines. All in a single file and with no
dependencies other than the Python Standard Library.

Homepage and documentation: http://wiki.github.com/defnull/bottle

Special thanks to Stefan Matthias Aust [http://github.com/sma]
  for his contribution to SimpelTemplate

Licence (MIT)
-------------

    Copyright (c) 2009, Marcel Hellkamp.

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in
    all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
    THE SOFTWARE.


Example
-------

    from bottle import route, run, request, response, send_file, abort

    @route('/')
    def hello_world():
        return 'Hello World!'

    @route('/hello/:name')
    def hello_name(name):
        return 'Hello %s!' % name

    @route('/hello', method='POST')
    def hello_post():
        name = request.POST['name']
        return 'Hello %s!' % name

    @route('/static/:filename#.*#')
    def static_file(filename):
        send_file(filename, root='/path/to/static/files/')

    run(host='localhost', port=8080)

"""

__author__ = 'Marcel Hellkamp'
__version__ = '0.4.10'
__license__ = 'MIT'


import cgi
import mimetypes
import os
import os.path
import sys
import traceback
import re
import random
import Cookie
import threading
import time
try:
    from urlparse import parse_qs
except ImportError:
    from cgi import parse_qs
try:
    import cPickle as pickle
except ImportError:
    import pickle
try:
    import anydbm as dbm
except ImportError:
    import dbm




# Exceptions and Events



class BottleException(Exception):
    """ A base class for exceptions used by bottle."""   
    """ 处理异常的基类"""
    pass


class HTTPError(BottleException):
    """ A way to break the execution and instantly jump to an error handler. """    
	''' 用于处理http错误，例如：http返回码是404，会显示“找不到此页面 '''

    def __init__(self, status, text):                                
        self.output = text      # http返回码输出的信息
        self.http_status = int(status)

    def __str__(self):
        return self.output


class BreakTheBottle(BottleException):
    """ Not an exception, but a straight jump out of the controller code.
    
    Causes the WSGIHandler to instantly call start_response() and return the
    content of output """   

    def __init__(self, output):
        self.output = output


class TemplateError(BottleException):
    """ Thrown by template engines during compilation of templates """
	pass
	






# WSGI abstraction: Request and response management

def WSGIHandler(environ, start_response):
    """The bottle WSGI-handler."""
	''' 使用wsgi规范 '''

    global request
    global response
    request.bind(environ)       # request = Request()下面已经定义了。实例调用Request()中的bind()方法
    response.bind()

    try:
        handler, args = match_url(request.path, request.method)         # 调用下面的match_url匹配请求的连接和方式
        if not handler:
            raise HTTPError(404, "Not found")       # 匹配不到路径。返回404
        output = handler(**args)
    except BreakTheBottle, shard:
        output = shard.output           # @@ ???
    except Exception, exception:
        response.status = getattr(exception, 'http_status', 500)
        errorhandler = ERROR_HANDLER.get(response.status, error_default)        
        # 返回key=response.status对应的value，如果不是500引起错误，调用error_default，自动查找response.status和对应的错误信息，返回到页面
        try:
            output = errorhandler(exception)
        except:
            output = "Exception within error handler! Application stopped."

        if response.status == 500:
            request._environ['wsgi.errors'].write("Error (500) on '%s': %s\n" % (request.path, exception))      
            # 遵循wsgi规范，environ有write方法。    read，readline，readlines，__iter__, flush(), write(), writelines() 这些方法都是wsgi规范中定义的
		
		db.close() # DB cleanup

    if hasattr(output, 'read'):         # 判断oute是否是一个file类型的。ps: file.read()
        fileoutput = output
        if 'wsgi.file_wrapper' in environ:
            output = environ['wsgi.file_wrapper'](fileoutput)
        else:
            output = iter(lambda: fileoutput.read(8192), '')        # output被转换成一个迭代器，读取8192个字节，直到为一个''(空字符串)
		''' 这应该是固定的写法，wsgi规范 '''
    elif isinstance(output, str):
        output = [output]       # 判断output是否是一个字符串，如果是，转换成list

    for c in response.COOKIES.values():
        response.header.add('Set-Cookie', c.OutputString())         # 调用HeaderDict中的add方法

    # finish
    status = '%d %s' % (response.status, HTTP_CODES[response.status])  # 固定格式 'http_code 响应的信息'  例如：'200 ok'
    start_response(status, list(response.header.items()))       # 调用服务器接口
    return output


class Request(threading.local):
    """ Represents a single request using thread-local namespace. """
    ''' request请求 '''

    def bind(self, environ):
        """ Binds the enviroment of the current request to this request handler """
        self._environ = environ
        self._GET = None
        self._POST = None
        self._GETPOST = None
        self._COOKIES = None
        self.path = self._environ.get('PATH_INFO', '/').strip()
        if not self.path.startswith('/'):
            self.path = '/' + self.path

    @property
    def method(self):
        ''' Returns the request method (GET,POST,PUT,DELETE,...) '''
        return self._environ.get('REQUEST_METHOD', 'GET').upper()       # 获取到的methon改成大写，默认是GET

    @property
    def query_string(self):
        ''' Content of QUERY_STRING '''
        return self._environ.get('QUERY_STRING', '')        # 找不到就返回空字符串
    @property
    def input_length(self):
        ''' Content of CONTENT_LENGTH '''       
        ''' header信息中Content-Length，默认是0 '''
        try:
            return int(self._environ.get('CONTENT_LENGTH', '0'))
        except ValueError:
            return 0

    @property
    def GET(self):
        """Returns a dict with GET parameters."""       
        ''' get请求方式 '''
		if self._GET is None:
            raw_dict = parse_qs(self.query_string, keep_blank_values=1)         
            # 解析url中的查询语句，返回一个字典。查询的key和对应value，value是list
            self._GET = {}
            for key, value in raw_dict.items():
                if len(value) == 1:
                    self._GET[key] = value[0]       # value[0]是一个字符串。
				else:
                    self._GET[key] = value
        return self._GET

    @property
    def POST(self):
        """Returns a dict with parsed POST data."""
		''' post请求方式 '''
        if self._POST is None:
            raw_data = cgi.FieldStorage(fp=self._environ['wsgi.input'], environ=self._environ)      
            # wsgi.input是environ中的变量，是environ字典必须包含的，表单数据或者上传数据都是从wsgi.input中取到的。  
            # 获取需要发送的数据。通过FieldStorage打包成字典。
            self._POST = {}
            if raw_data:
                for key in raw_data:
                    if isinstance(raw_data[key], list):
                        self._POST[key] = [v.value for v in raw_data[key]]      # 遍历raw_date，key相对的值传递给self._POST
                    elif raw_data[key].filename:        # ? filename是哪块的属性？
                        self._POST[key] = raw_data[key]
                    else:
                        self._POST[key] = raw_data[key].value
        return self._POST

    @property
    def params(self):
        ''' Returns a mix of GET and POST data. POST overwrites GET '''
        ''' post和get混合发送。post把get的内容覆盖掉 '''
        if self._GETPOST is None:
            self._GETPOST = dict(self.GET)
            self._GETPOST.update(dict(self.POST))
        return self._GETPOST

    @property
    def COOKIES(self):
        """Returns a dict with COOKIES."""
        if self._COOKIES is None:
            raw_dict = Cookie.SimpleCookie(self._environ.get('HTTP_COOKIE',''))     # 获取到cookie的值
            self._COOKIES = {}
            for cookie in raw_dict.values():
                self._COOKIES[cookie.key] = cookie.value        # 把value传递给self._cookie,然后通过以cookie的方法是发送
        return self._COOKIES


class Response(threading.local):
    """ Represents a single response using thread-local namespace. """
	''' response的属性 '''

    def bind(self):
        """ Clears old data and creates a brand new Response object """
        self._COOKIES = None
        self.status = 200
        self.header = HeaderDict()
        self.content_type = 'text/html'
        self.error = None
	
    @property
    def COOKIES(self):
		''' 调用Cookie模块处理cookie问题 '''
        if not self._COOKIES:
            self._COOKIES = Cookie.SimpleCookie()

        return self._COOKIES

    def set_cookie(self, key, value, **kargs):
        """ Sets a Cookie. Optional settings: expires, path, comment, domain, max-age, secure, version, httponly """
        self.COOKIES[key] = value       # cookie中各项类别的值
        for k in kargs:
            self.COOKIES[key][k] = kargs[k]

    def get_content_type(self):
        '''Gives access to the 'Content-Type' header and defaults to 'text/html'.'''
		''' 默认的Content-Type是text/html '''
        return self.header['Content-Type']
        
    def set_content_type(self, value):
        ''' 设置Content-Type的值为变量value '''
        self.header['Content-Type'] = value
        
    content_type = property(get_content_type, set_content_type, None, get_content_type.__doc__)
	

class HeaderDict(dict):
    ''' A dictionary with case insensitive (titled) keys.
    
    You may add a list of strings to send multible headers with the same name.'''
    
    
    def __setitem__(self, key, value):      # 类的描述
        return dict.__setitem__(self,key.title(), value)
    def __getitem__(self, key):
        return dict.__getitem__(self,key.title())
    def __delitem__(self, key):
        return dict.__delitem__(self,key.title())
    def __contains__(self, key):
        return dict.__contains__(self,key.title())

    def items(self):
        """ Returns a list of (key, value) tuples """
        for key, values in dict.items(self):
            if not isinstance(values, list):        # 如果values不是list就转换成list
                values = [values]
            for value in values:
                yield (key, str(value))     # 生成key对应的value的元组
                
    def add(self, key, value):
        """ Adds a new header without deleting old ones """
        ''' 添加header信息 '''
		if isinstance(value, list):
            for v in value:
                self.add(key, v)        # 递归调用add
        elif key in self:
            if isinstance(self[key], list):         # self[key]必须是一个list
                self[key].append(value)
            else:
                self[key] = [self[key], value]
        else:
          self[key] = [value]


def abort(code=500, text='Unknown Error: Appliction stopped.'):			
    """ Aborts execution and causes a HTTP error. """
    ''' 根据html返回码，抛出html返回码及相应的错误信息 '''
    raise HTTPError(code, text)


def redirect(url, code=307):							
	''' 重定向url，如果response.status的值是307，就重定向到指定的url，抛出实例的输出内容
     “也可以指定code的值，例如，如果code=404，就重定向某个url”
    '''

	""" Aborts execution and causes a 307 redirect """
    
    response.status = code
    response.header['Location'] = url
    raise BreakTheBottle("")


def send_file(filename, root, guessmime = True, mimetype = 'text/plain'):
    """ Aborts execution and sends a static files as response. """
    root = os.path.abspath(root) + '/'      
    # 取root绝对路径，在尾部加上'/'， 例如：/root/ ----> /var/www/html/root/
    
    filename = os.path.normpath(filename).strip('/')        
    # 把路径中的filename两边的下划线去掉
    
    filename = os.path.join(root, filename)     
    # filename成为一个绝对路径
    
    if not filename.startswith(root):
        abort(401, "Access denied.")        
        # 如果filename的路径不是root开头的，就调用abort函数，抛出一个401页面错误

    if not os.path.exists(filename) or not os.path.isfile(filename):
        abort(404, "File does not exist.")      
        # 测试当前的路径目录中是否存在filename或者这个filename是否是个文件，如果不存在或者不是，就调用abort函数，抛出一个404页面

    if not os.access(filename, os.R_OK):
        abort(401, "You do not have permission to access this file.")       
        # 判断filename是否可以读取的。如果不能读取，抛出401页面，提示没有权限

    if guessmime:
        guess = mimetypes.guess_type(filename)[0]       # 如果guessmine参数存在，就猜测filename的文件类型
        if guess:
            response.content_type = guess
        elif mimetype:
            response.content_type = mimetype        # 是默认的文件类型
    elif mimetype:
        response.content_type = mimetype

    stats = os.stat(filename)		# 返回filename的stat的结构信息

    # TODO: HTTP_IF_MODIFIED_SINCE -> 304 (Thu, 02 Jul 2009 23:16:31 CEST)
    if 'Content-Length' not in response.header:
        response.header['Content-Length'] = stats.st_size       # 让http头信息中加入filename的大小
    if 'Last-Modified' not in response.header:
        ts = time.gmtime(stats.st_mtime)
        ts = time.strftime("%a, %d %b %Y %H:%M:%S +0000", ts)
        response.header['Last-Modified'] = ts       # 在http头信息中加入filename的最后修改时间

    raise BreakTheBottle(open(filename, 'r'))	    # 输出这个文件内容，self.output=output    output = open(filename, 'r')





# Routing

def compile_route(route):
    """ Compiles a route string and returns a precompiled RegexObject.

    Routes may contain regular expressions with named groups to support url parameters.
    Example: '/user/(?P<id>[0-9]+)' will match '/user/5' with {'id':'5'}

    A more human readable syntax is supported too.
    Example: '/user/:id/:action' will match '/user/5/kiss' with {'id':'5', 'action':'kiss'}
    """
    route = route.strip().lstrip('$^/ ').rstrip('$^ ')      # 去除route中的空格,开头的'/'和尾部的空格
    route = re.sub(r':([a-zA-Z_]+)(?P<uniq>[^\w/])(?P<re>.+?)(?P=uniq)',r'(?P<\1>\g<re>)',route)        
    # re.sub做替换，如果route中出现前者，就把前者的内容替换成后者
	route = re.sub(r':([a-zA-Z_]+)',r'(?P<\1>[^/]+)', route)
    return re.compile('^/%s$' % route)      # 把route编译成re对象


def match_url(url, method='GET'):
    """Returns the first matching handler and a parameter dict or (None, None).
    
    This reorders the ROUTING_REGEXP list every 1000 requests. To turn this off, use OPTIMIZER=False"""
    url = '/' + url.strip().lstrip("/")         # Search for static routes first
    
	route = ROUTES_SIMPLE.get(method,{}).get(url,None)      # route是路径，ROUTES_SIMPLE中如果没有method就返回一个空字典

    if route:
      return (route, {})
    
    # Now search regex 
    routes = ROUTES_REGEXP.get(method,[])       
    # ROUTES_REGEXP是一个dict，在这个dict查找method，如果找到返回method对应的value值，找不到则返回一个[]
	for i in xrange(len(routes)):
        match = routes[i][0].match(url)
		# 匹配url
        if match:
            handler = routes[i][1]
            if i > 0 and OPTIMIZER and random.random() <= 0.001:
              # Every 1000 requests, we swap the matching route with its predecessor.
              # Frequently used routes will slowly wander up the list.
              routes[i-1], routes[i] = routes[i], routes[i-1]
            return (handler, match.groupdict())
    return (None, None)


def add_route(route, handler, method='GET', simple=False):
    """ Adds a new route to the route mappings.

        Example:
        def hello():
          return "Hello world!"
        add_route(r'/hello', hello)"""
    method = method.strip().upper()     # 规范化method，将小写改成大写

    if re.match(r'^/(\w+/)*\w*$', route) or simple:
        ROUTES_SIMPLE.setdefault(method, {})[route] = handler      
        # 如果匹配的route存在或者simple=False，ROUTES_SIMPLE中就增加key=route value=handler。如果存在就修改
    else:
        route = compile_route(route)        # 调用compile_route函数
		ROUTES_REGEXP.setdefault(method, []).append([route, handler])
		

def route(url, **kargs):
    """ Decorator for request handler. Same as add_route(url, handler)."""      
    ''' 在试用的时候作为装饰器使用 @route，功能包括：添加url映射，method方法等 '''
	def wrapper(handler):
        add_route(url, handler, **kargs)
        return handler
    return wrapper


def validate(**vkargs):
    ''' Validates and manipulates keyword arguments by user defined callables 
    and handles ValueError and missing arguments by raising HTTPError(400) '''
    
	'''  装饰器功能, 数据验证。例如：form表单，数据库存取数据。 '''
	
	def decorator(func):
        def wrapper(**kargs):
            for key in vkargs:
                if key not in kargs:
                    abort(403, 'Missing parameter: %s' % key)
                try:
                    kargs[key] = vkargs[key](kargs[key])
                except ValueError, e:
                    abort(403, 'Wrong parameter format for: %s' % key)
            return func(**kargs)
        return wrapper
    return decorator






# Error handling

def set_error_handler(code, handler):
    """ Sets a new error handler. """
    code = int(code)
    ERROR_HANDLER[code] = handler       # 增加新的http错误编码和相应的处理函数


def error(code=500):
    """ Decorator for error handler. Same as set_error_handler(code, handler)."""
	''' 装饰器作用，避免重复调用set_error_handler方法产生大量重复代码 '''
    def wrapper(handler):
        set_error_handler(code, handler)
        return handler
    return wrapper






# Server adapter

'''
	bottle的server是可以选择web服务类型。作者提供几种，可以在调用run()的时候修改
'''


class ServerAdapter(object):        # 初始化一个服务器设置的父类
    def __init__(self, host='127.0.0.1', port=8080, **kargs):
        self.host = host
        self.port = int(port)
        self.options = kargs

    def __repr__(self):
        return "%s (%s:%d)" % (self.__class__.__name__, self.host, self.port)

    def run(self, handler):
        pass


class WSGIRefServer(ServerAdapter):

    def run(self, handler):
        from wsgiref.simple_server import make_server
        srv = make_server(self.host, self.port, handler)        # 定义srv是一个wsgi服务器
        srv.serve_forever()         # 响应请求，直到结束


class CherryPyServer(ServerAdapter):
    def run(self, handler):
        from cherrypy import wsgiserver           # 导入cherrypy框架总的wsgiserver类
        server = wsgiserver.CherryPyWSGIServer((self.host, self.port), handler)     # 调用cherrypu中的 wsigiserver.CherryPyWSGIServer 服务
		server.start()      # 开始服务

class FlupServer(ServerAdapter):
    def run(self, handler):
       from flup.server.fcgi import WSGIServer
       WSGIServer(handler, bindAddress=(self.host, self.port)).run()        # 运行WSGIServer


class PasteServer(ServerAdapter):
    def run(self, handler):
        from paste import httpserver        # paste是极精简的WSGI server
        from paste.translogger import TransLogger
        app = TransLogger(handler)      # 一个日志中间件，将handler所有请求都通过这个中间件记录下来
		httpserver.serve(app, host=self.host, port=str(self.port))      # 通过WSGI接口启动服务

class FapwsServer(ServerAdapter):
    """ Extreamly fast Webserver using libev (see http://william-os4y.livejournal.com/)
        Experimental ... """
    def run(self, handler):
        import fapws._evwsgi as evwsgi      # fapws兼容WSGI的服务器，小而快速，可处理大并连接
        from fapws import base
        import sys
        evwsgi.start(self.host, self.port)      # 设置host和端口
        evwsgi.set_base_module(base)        # base将要开始工作，ps：本人认为类似__init__含义，初始化一下，然后就开工作了
        def app(environ, start_response):
            environ['wsgi.multiprocess'] = False
            return handler(environ, start_response)
        evwsgi.wsgi_cb(('',app))    # ''内是映射的url相对路径。
        evwsgi.run()        # 运行fapws服务


def run(server=WSGIRefServer, host='127.0.0.1', port=8080, optinmize = False, **kargs):
    """ Runs bottle as a web server, using Python's built-in wsgiref implementation by default.
    
    You may choose between WSGIRefServer, CherryPyServer, FlupServer and
    PasteServer or write your own server adapter.
    """
    global OPTIMIZER
    
    OPTIMIZER = bool(optinmize)
    quiet = bool('quiet' in kargs and kargs['quiet'])

    # Instanciate server, if it is a class instead of an instance
    if isinstance(server, type) and issubclass(server, ServerAdapter):      # 判断server的类型，是否是ServerAdapter的子类。如果是，执行下面的语句
        server = server(host=host, port=port, **kargs)

    if not isinstance(server, ServerAdapter):       # 如果server不是指定那几种服务类型，就抛出一个异常。
        raise RuntimeError("Server must be a subclass of ServerAdapter")

    if not quiet:       # 如果用户的代码没有问题就显示出执行的信息
        print 'Bottle server starting up (using %s)...' % repr(server)
        print 'Listening on http://%s:%d/' % (server.host, server.port)
        print 'Use Ctrl-C to quit.'
        print

    try:
        server.run(WSGIHandler)     # 运行服务
	except KeyboardInterrupt:       # Ctrl-C 引发一个KeyboardInterrupt异常。停止服务
		print "Shuting down..." 


# Templates

class TemplateError(BottleException): pass      # 设置模版错误的基类
class TemplateNotFoundError(BottleException): pass


class BaseTemplate(object):      # 父模版，用于映射模版名称，模版路径
	def __init__(self, template='', filename='<template>'):
        self.source = filename
        if self.source != '<template>':
            fp = open(filename)
            template = fp.read()
            fp.close()
        self.parse(template)
    def parse(self, template): raise NotImplementedError
    def render(self, **args): raise NotImplementedError     # 直接调用父类就会抛出 NotImplementedError错误.   后面应该都是直接调用子类自己parse和render
    @classmethod
    def find(cls, name):
        files = [path % name for path in TEMPLATE_PATH if os.path.isfile(path % name)]
		# 查找模版的路径
        if files:
            return cls(filename = files[0])
        else:
            raise TemplateError('Template not found: %s' % repr(name))


class MakoTemplate(BaseTemplate):
    def parse(self, template):
        from mako.template import Template      # 导入进来maketemplate库
        self.tpl = Template(template)       # 初始化一个实例，把template传递进来。mako就会自动的解析template
 
    def render(self, **args):
        return self.tpl.render(**args)      # 提交到browser，显示到页面

class SimpleTemplate(BaseTemplate):

    re_python = re.compile(r'^\s*%\s*(?:(if|elif|else|try|except|finally|for|while|with|def|class)|(include.*)|(end.*)|(.*))')
	# 模版中可以使用的python代码

	re_inline = re.compile(r'\{\{(.*?)\}\}')
    dedent_keywords = ('elif', 'else', 'except', 'finally')

    def parse(self, template):
		''' 解析模版 '''
        indent = 0
        strbuffer = []
        code = []
        self.subtemplates = {}
        class PyStmt(str):
            def __repr__(self): return 'str(' + self + ')'
        def flush():
            if len(strbuffer):      # 如果strbuffer中有xxx（东西），就把它插入到code中，然后清空strbutter
                code.append(" " * indent + "stdout.append(%s)" % repr(''.join(strbuffer)))
                code.append("\n" * len(strbuffer)) # to preserve line numbers 
                del strbuffer[:]

        for line in template.splitlines(True):   # 在解析关键字，splitlines返回的是一个列表，根据'\n'分割
            m = self.re_python.match(line)
            if m:
                flush()
                keyword, include, end, statement = m.groups()
                if keyword:
                    if keyword in self.dedent_keywords:
                        indent -= 1
                    code.append(" " * indent + line[m.start(1):])
                    indent += 1
                elif include:
                    tmp = line[m.end(2):].strip().split(None, 1)
                    name = tmp[0]
                    args = tmp[1:] and tmp[1] or ''
                    self.subtemplates[name] = SimpleTemplate.find(name)
                    code.append(" " * indent + "stdout.append(_subtemplates[%s].render(%s))\n" % (repr(name), args))
                elif end:
                    indent -= 1
                    code.append(" " * indent + '#' + line[m.start(3):])
                elif statement:
                    code.append(" " * indent + line[m.start(4):])
            else:
                splits = self.re_inline.split(line) # text, (expr, text)*
                if len(splits) == 1:
                    strbuffer.append(line)
                else:
                    flush()
                    for i in xrange(1, len(splits), 2):
                        splits[i] = PyStmt(splits[i])
                    code.append(" " * indent + "stdout.extend(%s)\n" % repr(splits))
        flush()
        self.co = compile("".join(code), self.source, 'exec')

    def render(self, **args):
        ''' Returns the rendered template using keyword arguments as local variables. '''
        args['stdout'] = []
        args['_subtemplates'] = self.subtemplates
        eval(self.co, args, globals())
        return ''.join(args['stdout'])


def template(template, template_adapter=SimpleTemplate, **args):
    ''' Returns a string from a template '''
	''' 可以选择模版解析的类。默认是SimplerTemplate '''
    if template not in TEMPLATES:
        if template.find("\n") == -1 and template.find("{") == -1 and template.find("%") == -1:
            try:
                TEMPLATES[template] = template_adapter.find(template)
            except TemplateNotFoundError: pass
        else:
            TEMPLATES[template] = template_adapter(template)
    if template not in TEMPLATES:
        abort(500, 'Template not found')
    args['abort'] = abort
    args['request'] = request
    args['response'] = response
    return TEMPLATES[template].render(**args)


def mako_template(template_name, **args):
    return template(template_name, template_adapter=MakoTemplate, **args)






# Database

class BottleBucket(object):
    '''Memory-caching wrapper around anydbm'''
	''' 对映射和数据库的一些操作 '''
    def __init__(self, name):
        self.__dict__['name'] = name
        self.__dict__['db'] = dbm.open(DB_PATH + '/%s.db' % name, 'c')          #  打开当前目录下的name.db, 'c' 表示有读写权限，如果没有这个数据库就创建一个。
        self.__dict__['mmap'] = {}
            
    def __getitem__(self, key):
        if key not in self.mmap:
            self.mmap[key] = pickle.loads(self.db[key])     # 序列化db[key]
        return self.mmap[key]
    
    def __setitem__(self, key, value):
        self.mmap[key] = value
    
    def __delitem__(self, key):
        if key in self.mmap:
            del self.mmap[key]
        del self.db[key]

    def __getattr__(self, key):
        try: return self[key]
        except KeyError: raise AttributeError(key)

    def __setattr__(self, key, value):
        self[key] = value

    def __delattr__(self, key):
        try: del self[key]
        except KeyError: raise AttributeError(key)

    def __iter__(self):
        return iter(set(self.db.keys() + self.mmap.keys()))
    
    def __contains__(self, key):
        return bool(key in self.keys())
  
    def __len__(self):
        return len(self.keys())

    def keys(self):
        return list(iter(self))

    def save(self):
        self.close()
        self.__init__(self.name)
    
    def close(self):
        for key in self.mmap.keys():
            pvalue = pickle.dumps(self.mmap[key], pickle.HIGHEST_PROTOCOL)
            if key not in self.db or pvalue != self.db[key]:
                self.db[key] = pvalue
        self.mmap.clear()       # 清空mmap这个字典
        self.db.close()
        
    def clear(self):
        for key in self.db.keys():
            del self.db[key]
        self.mmap.clear()
        
    def update(self, other):
        self.mmap.update(other)

    def get(self, key, default=None):
        try:
            return self[key]
        except KeyError:
            if default:
                return default
            raise


class BottleDB(threading.local):
    '''Holds multible BottleBucket instances in a thread-local way.'''
    def __init__(self):
        self.__dict__['open'] = {}
        
    def __getitem__(self, key):
        if key not in self.open and not key.startswith('_'):        # 如果 key 没有在open中 而且 以 '_' 开头的key不存在，就实例一个BottleBucket的实例
			self.open[key] = BottleBucket(key)
        return self.open[key]

    def __setitem__(self, key, value):
		''' self.open[key]只能是dict对象或者BottleBucket对象 '''

        if isinstance(value, BottleBucket):     # 判断value是不是BottleBucket对象
            self.open[key] = value
        elif hasattr(value, 'items'):       # 判断value有没有items属性。
            if key not in self.open:
                self.open[key] = BottleBucket(key)

            self.open[key].clear()      # 清空open[key]的值
            for k, v in value.items():      # 遍历value的key-value
                self.open[key][k] = v
        else:
            raise ValueError("Only dicts and BottleBuckets are allowed.")

    def __delitem__(self, key):
        if key not in self.open:
            self.open[key].clear()
            self.open[key].save()
            del self.open[key]          # 删除self.open[key]

    def __getattr__(self, key):
        try: return self[key]
        except KeyError: raise AttributeError(key)

    def __setattr__(self, key, value):
        self[key] = value

    def __delattr__(self, key):
        try: del self[key]
        except KeyError: raise AttributeError(key)

    def save(self):
        self.close()
        self.__init__()
    
    def close(self):
        for db in self.open.values():
            db.close()
        self.open.clear()
		# 清空open

# 为啥要删除self.open[key]的value？



# Modul initialization

DB_PATH = './'              # 数据库默认的路径
DEBUG = False
OPTIMIZER = False
TEMPLATE_PATH = ['./%s.tpl', './views/%s.tpl']          # template的默认搜索路径
TEMPLATES = {}

ROUTES_SIMPLE = {}          # 以{"r'/url'":hello}形式存储url及其映射的函数

ROUTES_REGEXP = {}          # 以 {'POST':[r'/url', hello]}形式存储url映射

ERROR_HANDLER = {}          # html相应的返回码对应相应的处理函数


HTTP_CODES = {
    100: 'CONTINUE',
    101: 'SWITCHING PROTOCOLS',
    200: 'OK',
    201: 'CREATED',
    202: 'ACCEPTED',
    203: 'NON-AUTHORITATIVE INFORMATION',
    204: 'NO CONTENT',
    205: 'RESET CONTENT',
    206: 'PARTIAL CONTENT',
    300: 'MULTIPLE CHOICES',
    301: 'MOVED PERMANENTLY',
    302: 'FOUND',
    303: 'SEE OTHER',
    304: 'NOT MODIFIED',
    305: 'USE PROXY',
    306: 'RESERVED',
    307: 'TEMPORARY REDIRECT',
    400: 'BAD REQUEST',
    401: 'UNAUTHORIZED',
    402: 'PAYMENT REQUIRED',
    403: 'FORBIDDEN',
    404: 'NOT FOUND',
    405: 'METHOD NOT ALLOWED',
    406: 'NOT ACCEPTABLE',
    407: 'PROXY AUTHENTICATION REQUIRED',
    408: 'REQUEST TIMEOUT',
    409: 'CONFLICT',
    410: 'GONE',
    411: 'LENGTH REQUIRED',
    412: 'PRECONDITION FAILED',
    413: 'REQUEST ENTITY TOO LARGE',
    414: 'REQUEST-URI TOO LONG',
    415: 'UNSUPPORTED MEDIA TYPE',
    416: 'REQUESTED RANGE NOT SATISFIABLE',
    417: 'EXPECTATION FAILED',
    500: 'INTERNAL SERVER ERROR',
    501: 'NOT IMPLEMENTED',
    502: 'BAD GATEWAY',
    503: 'SERVICE UNAVAILABLE',
    504: 'GATEWAY TIMEOUT',
    505: 'HTTP VERSION NOT SUPPORTED',
}

request = Request()
response = Response()
db = BottleDB()
local = threading.local()


@error(500)
def error500(exception):
    """If an exception is thrown, deal with it and present an error page."""
    if DEBUG:       # 如果开启DEBUG模式
        return "<br>\n".join(traceback.format_exc(10).splitlines()).replace('  ','&nbsp;&nbsp;')
    else:
        return """<b>Error:</b> Internal server error."""

def error_default(exception):
    status = response.status
    name = HTTP_CODES.get(status,'Unknown').title()
    url = request.path
    """If an exception is thrown, deal with it and present an error page."""
    yield template('<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">'+\
      '<html><head><title>Error {{status}}: {{msg}}</title>'+\
      '</head><body><h1>Error {{status}}: {{msg}}</h1>'+\
      '<p>Sorry, the requested URL {{url}} caused an error.</p>', 
        status=status,
        msg=name,
        url=url             
      )
	
    # 生成一个template对象。显示错误页面
	if hasattr(exception, 'output'):
      yield exception.output
    yield '</body></html>'          # 闭合<body><html> 标签


# 数据库

'''
自带的bottleDB 可以实现简单的数据库功能，db = BottleDB() ,主要就是针对字典的操作，包括增加，修改，删除等。操作结束后调用save()方法保存数据
然后调用close()方法，关闭数据库。BottleBucket类，给定数据库名称name，然后根据默认数据库路径，寻找 name.db文件， 通过pickle把要存的数据序列化
存储到一个中间的变量mmap中，当要关闭数据库的时候，将数据反序列化存储到数据库文件中，以保存数据的完整性。
'''


# 匹配url

'''
通过调用match_url这个方法，用正则表达式进行匹配url。method默认的是get，也可以选用post。通过装饰器直接在应用中直接调用route方法,直接给入url的
路径route就会映射到对应的函数。
'''


# server

''' 
通过wsgi规范实现了http服务器执行bottle框架的功能。 其中需要传递的 变量都保存在environ字典中， 通过environ[key]调用数据。
run()方法中定义了server的类别，它调用WSGIRefServer中的run方法，将WSGIHandler加载过来， 过程如下：
    客户端发出请求，server端拿到数据后， 把url拆分成{'协议':'http/https','addr':'www.xxx.com', 'path':'/html/name', 'query-string':'?getname=name'} ，通过addr, path找到http服务器中配置文件（conf.d/*）（apache）中对应的配置项，根 据其中的python网站配置项， 通过发布处理器加载mod_python， 返回相应路径下python(或Web框架)的执行结果。使用wsgi服务器规范，发布处理器接口使用wsgi处理python代码，然后返回到浏览器页面。
'''




