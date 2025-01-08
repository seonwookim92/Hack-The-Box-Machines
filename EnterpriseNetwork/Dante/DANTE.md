---
tags: 
group: EnterpriseNetwork
---
![](https://app.hackthebox.com/images/icons/ic-prolabs/ic-dante-overview.svg)

- Machine : https://app.hackthebox.com/prolabs/dante


# Summary

### Credentials

| Idx | Int/Ext | User      | Password                    | Type  | Where to find | Where to use | Link                                                  |
| --- | ------- | --------- | --------------------------- | ----- | ------------- | ------------ | ----------------------------------------------------- |
| 1   | Ext     | james     | Toyota                      | plain | NIX01         | Wordpress    | [Link](DANTE.md#Find%20credential%20using%20`wpscan`) |
| 2   | Ext     | shaun     | password                    | plain | NIX01         | mysql        | [Link](DANTE.md#Find%20DB%20Credential)               |
| 3   | Ext     | balthazar | TheJoker12345!              | plain | NIX01         | mysql, ssh   |                                                       |
| 4   | Int     | margaret  | Welcome1!2@3#               | plain | NIX02         | ssh          |                                                       |
| 5   | Int     | frank     | TractorHeadtorchDeskmat     | plain | NIX02         | ssh          |                                                       |
| 6   | Int     | admin     | admin                       | plain | NIX04         | blog         |                                                       |
| 7   | Int     | ben       | Welcometomyblog             | plain | NIX04         | blog, ssh    |                                                       |
| 8   | Int     | admin     | password6543                | plain | NIX03         | Webmin       |                                                       |
| 9   | Int     | xadmin    | Peacemaker!                 | plain | DC01          | ssh          |                                                       |
| 10  | Int     | katwamba  | DishonestSupermanDiablo5679 | plain | DC01          | ssh          |                                                       |
|     |         |           |                             |       |               |              |                                                       |
|     |         |           |                             |       |               |              |                                                       |
|     |         |           |                             |       |               |              |                                                       |


### Target overview

| Idx | Host       | Status | Vuln                                                                                                                                                                                                            | Link                                                  |
| --- | ---------- | ------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------- |
| 1   | NIX01(100) | Owned  | - Wordpress Login brute forcing to find credential<br>- Wordpress Plugin to open a reverse shell<br>- Find credential in command line from `.bash_history`<br>- (privesc#1) PwnKit<br>- (privesc#2) SUID `find` | [Link](DANTE.md#Shell%20as%20`www-data`%20on%20NIX01) |
| 2   | SQL01(5)   | Pass   | - Just identified services                                                                                                                                                                                      | [Link](DANTE.md#172.16.1.5(SQL01))                    |
| 3   | NIX02(10)  | Owned  | - LFI to read `wp-config.php`<br>- Exploiting `vim` to escape from restricted shell<br>- Retrieve `Slack` exported data to obtain credential<br>- Python library Injection                                      | [Link](DANTE.md#172.16.1.10(NIX02))                   |
| 4   | NIX04(12)  | Owned  | - SQL Injection on Responsive Online Blog<br>- Exploit outdated `sudo`(1.8.27)                                                                                                                                  | [Link](DANTE.md#172.16.1.12(NIX04))                   |
| 5   | WS01(13)   | User   | - Obtain credential from `sql` file<br>- Exploit File Upload vulnerability in Sign-up page                                                                                                                      | [Link](DANTE.md#172.16.1.13(WS01))                    |
| 6   | NIX03(17)  | Owned  | - Webmin 1.900 Package Update exploit                                                                                                                                                                           | [Link](DANTE.md#172.16.1.17(NIX03))                   |
| 7   | ???(19)    | Pass   | - No valid credential yet...                                                                                                                                                                                    |                                                       |
|     | DC01(20)   |        |                                                                                                                                                                                                                 |                                                       |
|     | WS02(101)  | Pass   |                                                                                                                                                                                                                 |                                                       |
|     | WS03(102)  | Owned  |                                                                                                                                                                                                                 |                                                       |
|     |            |        |                                                                                                                                                                                                                 |                                                       |
|     |            |        |                                                                                                                                                                                                                 |                                                       |


### Vulnerability



---

### Details
- [External Penetration Testing](Details/External%20Penetration%20Testing.md)
- [Shell as www-data on NIX01](Details/Shell%20as%20www-data%20on%20NIX01.md)
- [172.16.1.100(NIX01)](Details/172.16.1.100(NIX01).md)
- [Pivotting](Details/Pivotting.md)
- [Internal Penetration Testing](Details/Internal%20Penetration%20Testing.md)
- [172.16.1.1(FW)](Details/172.16.1.1(FW).md)
- [172.16.1.5(SQL01)](Details/172.16.1.5(SQL01).md)
- [172.16.1.10(NIX02)](Details/172.16.1.10(NIX02).md)
- [172.16.1.12(NIX04)](Details/172.16.1.12(NIX04).md)
- [172.16.1.13(WS01)](Details/172.16.1.13(WS01).md)
- [172.16.1.17(NIX03)](Details/172.16.1.17(NIX03).md)
- [172.16.1.19](Details/172.16.1.19.md)
- [172.16.1.101(WS02)](Details/172.16.1.101(WS02).md)
- [172.16.1.20(DC01)](Details/172.16.1.20(DC01).md)


