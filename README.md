# wlan-deauth-attack
https://gitlab.com/gilgil/sns/-/wikis/deauth-attack/report-deauth-attack

### 과제
Deauth Attack 프로그램을 작성하라.

### 실행
```
syntax : deauth-attack <interface> <ap mac> [<station mac> [-auth]]
sample : deauth-attack mon0 00:11:22:33:44:55 66:77:88:99:AA:BB
```

### 상세
* \<ap mac\>만 명시되는 경우에는 AP broadcast frame을 발생시킨다.

* \<station mac\>까지 명시되는 경우에는 AP unicast, Station unicast frame을 발생시킨다.

* -auth 옵션이 주어지면 deauthentication이 아닌 authentication으로 공격한다(authentication frame 정보는 실제 일반 Station의 연결 과정에서 획득할 수 있다).


