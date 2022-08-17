# ElastAlert

## 使用 Elasticsearch 轻松灵活地发出警报
ElastAlert 是一个简单的框架，用于对来自 Elasticsearch 中的数据的异常、峰值或其他感兴趣的模式发出警报。

ElastAlert 适用于所有版本的 Elasticsearch。

在 Yelp，我们使用 Elasticsearch、Logstash 和 Kibana 来管理我们不断增加的数据和日志量。Kibana 非常适合可视化和查询数据，但我们很快意识到它需要一个配套工具来提醒我们数据中的不一致。出于这种需要，创建了 ElastAlert。

如果您将数据近乎实时地写入 Elasticsearch，并希望在该数据与特定模式匹配时收到警报，那么 ElastAlert 就是您的理想之选。如果您可以在 Kibana 中看到它，ElastAlert 可以对其发出警报。

## 概述
我们将 ElastAlert 设计为可靠、高度模块化且易于设置和配置。

它通过将 Elasticsearch 与两种类型的组件、规则类型和警报相结合来工作。Elasticsearch 会定期查询并将数据传递给规则类型，该类型确定何时找到匹配项。发生匹配时，会收到一个或多个警报，这些警报会根据匹配采取行动。

这是由一组规则配置的，每个规则定义一个查询、一个规则类型和一组警报。

ElastAlert 包含几种具有常见监控范例的规则类型：

- 匹配 Y 时间至少有 X 个事件的位置”（frequency类型）
- 当事件发生率增加或减少时匹配”（spike类型）
- 在 Y 时间少于 X 个事件时匹配”（flatline类型）
- 当某个字段匹配黑名单/白名单时匹配”（blacklist和whitelist类型）
- 匹配与给定过滤器匹配的任何事件”（any类型）
- 当一个字段在一段时间内有两个不同的值时匹配”（change类型）
- 当字段中出现从未见过的术语时匹配”（new_term类型）
- 当字段的唯一值数量高于或低于阈值（cardinality类型）时匹配

目前，我们内置了对以下警报方式的支持：
- 电子邮件
- JIRA
- 行动精灵
- 命令
- 嘻哈聊天
- 微软团队
- 松弛
- 电报
- 谷歌聊天
- AWS SNS
- 胜利者行动
- 寻呼机
- 寻呼树
- 外星酒店
- 特维利奥
- 吉特
- 线路通知
- 扎比克斯

