## Phpinfo Scanner
抓取phpinfo重要信息，搬砖小工具，无难度。。。
效果展示：
```
+------------------------+------------------------------------------------------------------------------------------+
| Web Path               | /var/www/html/info.php                                                                   |
| Server IP              | 172.16.72.131                                                                            |
| Software               | nginx/1.15.8                                                                             |
| PHP Version            | 7.0.33                                                                                   |
| System                 | Linux ubuntu 4.4.0-131-generic #157-Ubuntu SMP Thu Jul 12 15:51:36 UTC 2018 x86_64       |
| Server API             | FPM/FastCGI                                                                              |
| Registered PHP Streams | https, ftps, compress.zlib, compress.bzip2, php, file, glob, data, http, ftp, phar, zip  |
| Allow Url Include      | Off, Off                                                                                 |
| Short Open Tag         | On, On                                                                                   |
| Enable Dl              | On, On                                                                                   |
| Open Basedir           | no value, no value                                                                       |
| Session                | session.serialize_handler:       php,php                                                 |
|                        | session.upload_progress.enabled: On,On                                                   |
|                        | session.upload_progress.cleanup: On,On                                                   |
|                        | session.upload_progress.name:    PHP_SESSION_UPLOAD_PROGRESS,PHP_SESSION_UPLOAD_PROGRESS |
| Libxml Version         | 2.9.3                                                                                    |
| Disable Function       | no value                                                                                 |
| Extentions             | xdebug                                                                                   |
+------------------------+------------------------------------------------------------------------------------------+
+--------------------------------------------------------------+
| php 7.0: 移除dl; 不再支持asp_tag、<script language="php"> |
+--------------------------------------------------------------+
| SAPI为fpm，可能存在未授权访问漏洞                         |
+--------------------------------------------------------------+
| 支持phar协议，可扩展反序列化攻击面                        |
+--------------------------------------------------------------+
| libcurl支持gopher, dict协议                               |
+--------------------------------------------------------------+
| 可利用session.upload_progress上传临时文件然后包含         |
| 临时文件会立刻删除，需用条件竞争getshell                     |
+--------------------------------------------------------------+
```
