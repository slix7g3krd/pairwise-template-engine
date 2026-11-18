# pairwise-template-engine

邮件模板一支持用户自定义，SSTI 就能读服务器文件：模板字符串直接进引擎，`{{ ''.__class__.__mro__ }}` 能遍历到危险类；过滤器黑名单只查 `__import__`，attr/getitem 绕过；include 路径用用户输入，../ 能读任意模板；沙箱 globals 没清空，builtins 还能调用；自动转义关闭，变量里的 HTML 直接执行；模板编译结果按用户输入缓存，能污染其他租户；布局模板可由用户指定，能覆盖系统页头；宏定义里能调用任意函数；错误页回显模板源码和上下文；上下文对象把数据库连接传进去；eval 被封装成自定义过滤器；模板继承链没有深度限制；编码过滤器可被绕过；缓存键不含租户；渲染超时没有限制。security/template_engine.py 是核心，tests/test_template_engine.py 15个红。要修的是：逻辑模板与展示数据分离；属性访问白名单；过滤器白名单；include 路径白名单；清空 globals/builtins；默认转义；缓存键隔离；布局白名单；宏白名单；错误脱敏；上下文最小化；禁用 eval；继承深度；编码统一；渲染超时。

## 运行

```bash
python -m pytest tests -q
```

初始状态：15 个用例失败。修复实现使全部用例通过，不要修改 `tests/` 下的测试。

子方向：漏洞检测与攻防；任务类型：Bugfix；语言/框架：Python 3, pytest；环境可复现等级：无外部依赖。
