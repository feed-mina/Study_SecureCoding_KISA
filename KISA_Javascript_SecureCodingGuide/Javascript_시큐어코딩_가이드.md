#  제 1절 입력데이터 검증 및 표현

---
## SQL 삽입

데이터베이스 드라이버 사용 예제
다음은 사용자 입력값을 받아 원시 쿼리를 구성해 처리하는 안전하지 않은 코드 예시이다.
클라이언트에서 GET 요청의 인자로 전달된 아이디 값을 검증 없이 그대로 쿼리에 삽입하므로, 공격자가 정상적인 정수형 id 값 대신
`1 UNION SELECT group_concat(table_name) FROM information_schema.tables WHERE table_schema = database()`
와 같은 공격문을 전달할 경우 데이터베이스 내의 모든 테이블 이름이 조회된다.
이는 곧 공격자가 원하는 모든 쿼리를 실행 가능하다는 의미로 해석될 수 있다.

```javascript
// 커넥션 초기화 옵션은 생략함
const connect = mysql.createConnection(...)

router.get('/vuln/email', (req, res) => {
  const con = connection
  const userInput = req.query.id
  // 사용자로부터 입력받은 값을 검증 없이 그대로 쿼리에 사용
  const query = `select email from user where user_id = ${userInput}`
  con.query(query, (err, result) => {
    if (err) console.log(err)
    return res.send(result)
  })
})
```

데이터베이스 라이브러리가 인자화된 쿼리 기능을 지원할 경우 해당 기능을 사용해 쿼리를 생성해야 한다.
MySQL 라이브러리에서는 인자화된 쿼리 기능은 제공하지 않지만, `?` 형식으로 유사한 기능을 구현할 수 있다.
다음은 위 코드를 안전한 코드로 변환한 예시이다.

### ORM 사용 예제
express.js에서 많이 사용하는 Sequelize ORM은 인자화된 쿼리 방식을 사용하므로 SQL 삽입 공격으로부터 안전하다.
원시 SQL을 사용할 경우에도 바인딩 변수를 통해 입력값을 전달해야 한다.

#### 사용예제 코드 추가하기 ***

---

## 2. 코드 삽입
공격자가 소프트웨어의 의도된 동작을 변경하도록 임의 코드를 입력해 소프트웨어가 비정상적으로 동작하도록 하는 보안 약점을 말한다.
코드 삽입은 프로그래밍 언어 자체의 기능에 한해 이루어진다는 점에서 운영체제 명령어 삽입과 다르다.
공격자가 소프트웨어의 의도된 동작을 변경하도록 임의 코드를 삽입해, 소프트웨어가 비정상적으로 동작하도록 하는 보안 약점이다.

코드 삽입은 운영체제 명령어 삽입과 다르다.
프로그램에서 사용자의 입력값 내에 코드가 포함되는 것을 허용할 경우, 공격자는 개발자가 의도하지 않은 코드를 실행해 권한을 탈취하거나 인증 우회, 시스템 명령어 실행 등을 수행할 수 있다.

자바스크립트에서 코드 삽입 공격을 유발할 수 있는 함수로는 `eval()`, `setTimeout()`, `setInterval()` 등이 있다.
해당 함수의 인자를 면밀히 검증하지 않는 경우 공격자가 전달한 코드가 그대로 실행될 수 있다.

브라우저 위에서 동작하는 클라이언트 측 환경에는 주요 자원을 포함하는 서버와 달리 코드 입력 자체만으로는 큰 위협이 되지 않는다.

---

안전한 코드
동적 코드를 실행할 수 있는 함수를 사용하지 않는다.
필요 시 실행 가능한 동적 코드를 입력 값으로 받지 않도록 외부 입력값에 대해 화이트 리스트 기반 검증을 수행해야 한다.
또한 문자만 포함하도록 동적 코드에 사용되는 사용자 입력값을 필터링 하는 방법도 있다.
데이터와 명령어를 엄격히 분리해 처리하는 별도의 로직을 구현할 수도 있다.

---

코드 예제: 안전하지 않은 코드

```javascript
const express = require('express')

router.post("/vuln/server", (req, res) => {
  // 사용자로부터 전달받은 값을 그대로 eval 함수의 인자로 전달
  const data = eval(req.body.data)
  return res.send({ data })
})
```

외부로부터 입력받은 값을 검증 없이 사용할 경우 공격자는 JavaScript 코드를 통해 악성 기능 실행을 위한 라이브러리 로드 및 원격 대화형 쉘 등을 실행할 수 있다.

---

안전한 코드 예시

```javascript
const express = require('express')

function alphanumeric(input_text) {
  // 정규표현식 기반 문자열 검사
  const letterNumber = /^[0-9a-zA-Z]+$/
  if (input_text.match(letterNumber)) {
    return true
  } else {
    return false
  }
}

router.post("/patched/server", (req, res) => {
  let ret = null
  const { data } = req.body

  // 사용자 입력을 영문, 숫자로 제한
  if (alphanumeric(data)) {
    ret = eval(data)
  } else {
    ret = 'error'
  }
  return res.send({ ret })
})
```

---

eval 함수 설명
eval은 JavaScript에서 제공하는 내장 함수로, 문자열로 된 JavaScript 코드를 실제 코드처럼 실행한다.

```javascript
eval("2 + 2")            // 4 반환
eval("console.log('Hello')")   // Hello 출력
```

왜 위험할까?
eval은 아무 문자열이나 실행하기 때문에 사용자가 입력한 값을 그대로 넣으면 악성 코드도 실행될 수 있다.

```javascript
const userInput = "console.log('해킹')"
eval(userInput) // 사용자가 입력한 코드가 그대로 실행됨
```

따라서 실무에서는 사용을 권장하지 않는다.

대체 방법
단순 계산: Number, parseInt
JSON 구조: JSON.parse
동적 실행 필요: 함수 생성자 또는 안전한 라이브러리 사용

---

##  3. 경로 조작
   검증되지 않은 외부 입력값을 통해 파일 및 서버 등 시스템 자원(파일, 소켓 포트 등)에 대한 접근을 허용할 경우, 입력값 조작으로 보호된 자원에 임의로 접근할 수 있는 보안 약점이다.
   공격자는 자원 수정, 삭제, 시스템 정보 노출, 서비스 장애 등을 유발할 수 있다.

Node.js 기반 서버 프로그램의 경우 `fs` 및 `socket.io` 라이브러리를 통해 프로세스 및 소켓 연결을 제어할 수 있다.

안전한 코딩 기법
외부 입력값을 자원의 식별자로 사용할 경우 엄격히 검증하거나 화이트리스트 방식으로 제한해야 한다.
파일 경로 입력에 대해서는 `/`, `\`, `..` 등의 경로 순회 문자열을 제거해야 한다.

---

취약 예제

```javascript
const express = require('express')
const path = require('path')

router.get("/vuln/file", (req, res) => {
  const requestFile = req.query.file
  // 입력값 검증 없음
  fs.readFile(path.resolve(__dirname, requestFile), 'utf8', (err, data) => {
    if (err) {
      return res.send('error')
    }
    return res.send(data)
  })
})
```

공격 예:
`../../../../etc/passwd`

---

안전한 예제

```javascript
const express = require('express')
const io = require('socket.io')

router.get("/patched/socket", (req, res) => {
  const whitelist = ["ws://localhost", "ws://127.0.0.1"]

  if (whitelist.indexOf(req.query.url) < 0) {
    return res.send("wrong url")
  }

  try {
    const socket = io(req.query.url)
    return res.send(socket)
  } catch (err) {
    return res.send("[error] fail to connect")
  }
})
```

---

4. 크로스 사이트 스크립트(XSS)
5. 공격 스크립트가 포함된 게시물 등록
6. 공격 스크립트가 포함된 게시물 페이지 요청
7. 공격 스크립트가 포함된 캐시 응답

Cross-Site Scripting 공격은 웹사이트에 악성 스크립트를 삽입해 실행하도록 하는 공격 기법이다.

---

인자화된 쿼리(parameterization)
쿼리 구조와 값(data)을 분리하는 방식이다.
SQL 문장은 고정된 틀을 만들고, 값은 별도로 전달한다.
DB는 쿼리 구조와 입력값을 구분하기 때문에 SQL 삽입 공격이 불가능해진다.

예)

```sql
SELECT email FROM user WHERE user_id = ?
```

---

취약한 코드 → 안전한 코드 변환

```javascript
// 취약한 방식
const query = `SELECT email FROM user WHERE user_id = ${userInput}`
con.query(query, (err, result) => {...})

// 안전한 방식
const query = "SELECT email FROM user WHERE user_id = ?"
con.query(query, [userInput], (err, result) => {
  if (err) console.log(err)
  return res.send(result)
})
```

--- 
## 12. 서버사이드 요청 위조
아래는 요청한 내용 전체를
오타 모두 수정하여 자연스럽게 다시 쓰고
문장이 끝날 때마다 줄바꿈한 정리본이다.
(의미는 유지, 줄바꿈 정리 + 코드 정리)

---

내부망 중요 정보 획득
외부 접근이 차단된 Admin 페이지에 도메인 체크를 우회하여 접근하고 중요 정보를 획득하는 공격이다.
단축 URL을 이용하여 필터를 우회하거나, 도메인을 사설 IP로 설정하여 중요 정보를 획득할 수 있다.
또한 서버 내 파일도 열람할 수 있다.

예시 URL
http://sample_site.com/connect?url=[http://192.168.0.45/member/list.json](http://192.168.0.45/member/list.json)
http://sample_site.com/connect?url=[http://192.168.0.45/admin](http://192.168.0.45/admin)
http://sample_site.com/connect?url=http://sample_site.com"x@192.168.0.45/member/list.json
http://sample_site.com/connect?url=[http://bit.ly/sdjk3kjkl3](http://bit.ly/sdjk3kjkl3)
http://sample_site.com/connect?url=file:///etc/passwd

다음 예제는 사용자로부터 입력된 URL 주소를 검증 없이 사용하면 의도하지 않은 다른 서버의 자원에 접근할 수 있게 되는 취약한 코드를 보여준다.

```javascript
const request = require('request')

router.get("/vuln", async (req, res) => {
  const url = req.query.url
  // 사용자 입력 주소를 검증하지 않고 요청 수행 후 응답을 그대로 반환함
  await request(url, (err, response) => {
    const resData = response.body
    return res.send(resData)
  })
})
```

---

다음은 안전한 코드 예시이다.
화이트리스트 기반 URL 검증을 통해 외부 입력값을 임의로 조작할 수 없도록 한다.

```javascript
router.get("/patched", async (req, res) => {
  const url = req.query.url
  const whitelist = ['www.example.com', 'www.safe.com']

  // 화이트리스트 검증 후 요청 허용
  if (whitelist.includes(url)) {
    await request(url, (err, response) => {
      const resData = response.body
      return res.send(resData)
    })
  } else {
    return res.send('잘못된 요청입니다.')
  }
})
```

---

## 13. 보안기능 결정에 사용되는 부적절한 입력값
    공격자가 Cookie, 환경변수, Hidden Field 등 변조 가능한 입력값을 조작하여 보안 인증 절차를 우회하는 공격이다.
    응용 프로그램이 외부 입력값을 신뢰하는 것을 전제로 보호 메커니즘을 사용할 경우, 공격자는 입력값 조작을 통해 보호 메커니즘을 우회할 수 있다.

웹 애플리케이션은 쿠키, 환경변수, hidden field가 조작되지 않을 것이라고 가정하지만, 공격자는 다양한 방식으로 입력값을 변경할 수 있다.
조작된 입력값은 탐지되지 않을 수 있으며, 인증·인가와 같은 중요한 보안 결정이 이러한 입력값을 기반으로 수행된다면 보안을 우회할 수 있다.

따라서 인증·인가 등 중요한 보안 기능 결정 과정에서는 데이터를 암호화 및 무결성 체크로 보호하고, 외부 입력값을 신뢰해서는 안 된다.
민감한 데이터(세션 정보 등)는 클라이언트가 아닌 서버에 저장해야 한다.
인증 절차가 여러 단계라면 각 단계별로 값이 변조되지 않았는지 검증해야 한다.

보안 설계 관점에서 신뢰할 수 없는 입력값이 내부로 들어올 수 있는 지점을 분석하고, 보안 기능 결정에 사용되는 입력값을 식별하여 입력값 의존 구조를 제거해야 한다.

---

취약한 코드 예시
쿠키에 저장된 권한 등급을 기반으로 관리자 여부를 판단하는 방식은 취약하다.

```javascript
router.get("/admin", (req, res) => {
  // 쿠키에서 권한 정보를 가져옴
  const role = req.cookies.role

  if (role === "admin") {
    // 쿠키 기반 권한정보로 관리자 페이지 접속 처리
    return res.render('admin', { title: '관리자 페이지' })
  } else {
    return res.send("사용 권한이 없습니다.")
  }
})
```

---

안전한 코드 예시
중요 기능 수행을 결정하는 데이터는 변조 가능한 쿠키 대신 세션에 저장해야 한다.

```javascript
app.use(session({
  secret: 'test',
  resave: true,
  saveUninitialized: true,
  store: new MemoryStore({ checkPeriod: 60 * 60 * 1000 })
}))

router.get("/patched", (req, res) => {
  const role = req.session.role

  if (role === "admin") {
    return res.render('admin', { title: '관리자 페이지' })
  } else {
    return res.send('사용 권한이 없습니다.')
  }
})
```

 
---

 # 재2절 보안기능

 ## 1. 적절한 인증 없는 중요 기능 허용
중요정보(금융정보, 개인정보, 인증 정보 등)가 적절한 인증 없이 열람 또는 변경 가능한 경우 발생하는 보안 약점이다.

---

## 2. 부적절한 인가
중요 자원에 접근할 때 적절한 제어가 없어 비인가 사용자의 접근이 가능한 보안 약점이다.
중요한 자원에 대한 잘못된 권한 설정으로 인해 접근 권한을 부여하지 않거나 잘못 부여하면 중요 정보가 노출·수정될 수 있다.

---

## 4. 취약한 암호화 알고리즘 사용
중요정보(비밀번호, 개인정보 등)를 전송 시 암호화 또는 안전한 통신 채널을 이용하지 않거나, 저장 시 암호화하지 않아 정보가 노출될 수 있는 보안 약점이다.

```javascript
function getEncText(plainText, key, iv) {
  // 권장 알고리즘인 AES를 사용하여 안전함
  const cipherAes = crypto.createCipheriv('aes-256-cbc', key, iv)
  const encryptedData = cipherAes.update(plainText, 'utf8', 'base64')
  const finalEncryptedData = cipherAes.final('base64')
  return encryptedData + finalEncryptedData
}
```

다음 예제는 취약한 MD5 해시 함수를 사용하는 예시이다.
MD5와 같이 수학적으로 취약한 것으로 확인된 해시 함수는 역계산은 불가능하지만, 레인보우 테이블 등을 이용하여 평문을 알아낼 수 있다.

```javascript
const crypto = require("crypto")

function makeMd5(plainText) {
  const hashText = crypto.createHash('md5').update(plainText).digest('hex')
  return hashText
}
```

---

안전한 SHA-256 알고리즘 사용 예시

```javascript
const crypto = require('crypto')

function makeSha256(plainText) {
  const salt = crypto.randomBytes(16).toString('hex')
  const hashText = crypto.createHash('sha256').update(plainText + salt).digest('hex')
  return hashText
}
```

---

잘못된 예: 암호화하지 않은 비밀번호를 DB에 저장하는 경우

```javascript
function updatePass(dbconn, password, user_id) {
  // 암호화되지 않은 비밀번호를 DB에 저장하는 경우 위험함
  const sql = 'UPDATE user SET password=? WHERE user_id=?'
  const params = [password, user_id]
  dbconn.query(sql, params, function (err, rows, fields) {
    if (err) console.log(err)
  })
}
```

---
## 5. 암호화 되지 않은 중요정보
안전한 예제: SHA-256 해시 + salt 사용

```javascript
const crypto = require('crypto')

function updatePass(dbconn, password, user_id, salt) {
  const sql = 'UPDATE user SET password=? WHERE user_id=?'
  const hashPw = crypto.createHash('sha256').update(password + salt, 'utf-8').digest('hex')
  const params = [hashPw, user_id]

  dbconn.query(sql, params, function (err, rows, fields) {
    if (err) console.log(err)
  })
}
```


중요정보 평문 전송
인자값으로 전달 받은 패스워드를 암호화 없이 네트워크를 통해 전송하는 경우 패킷 스니핑을 통해 패스워드가 노출될 수 있다.

```javascript
const { io } = require("socket.io-client")
const crypto = require("crypto")
const socket = io("http://localhost:3000")

const PASSWORD = getPassword()

function aesEncrypt(plainText) {
  const key = getCryptKey()
  const iv = getCryptIV()
  const cipherAes = crypto.createCipheriv('aes-256-cbc', key, iv)
  const encryptedData = cipherAes.update(plainText, 'utf8', 'base64')
  const finalEncryptedData = cipherAes.final('base64')
  return encryptedData + finalEncryptedData
}

function sendPassword(password) {
  // 패스워드 등 중요 정보는 암호화하여 전송하는 것이 안전함
  const encPassword = aesEncrypt(password)
  socket.emit("password", encPassword)
}
```

```javascript
socket.on("password", function (data) {
  if (data === 'success') {
    console.log('success to send a message')
  }
})
```

---

## 6. 하드코딩된 중요정보
프로그램 코드 내부에 하드코드된 패스워드를 포함하여 내부 인증 또는 외부 컴포넌트와 통신에 사용하는 경우, 관리자의 정보가 노출될 수 있어 위험하다.
하드코드된 암호화 키를 사용해 암호화를 수행하면 암호화된 정보가 유출될 가능성이 높아진다.
해시를 계산하여 저장하더라도 역계산이 가능하거나 무차별 대입 공격(Brute force)에는 취약할 수 있다.

패스워드는 암호화 후 별도의 파일에 저장하여 사용한다.
중요정보 암호화 시 상수가 아닌 암호화 키를 사용해야 한다.
암호화가 잘 되었더라도 코드 내부에 상수 형태의 암호화 키를 주석 또는 소스 코드에 저장하지 않아야 한다.

---  

---

## 스푸핑(Spoofing)과 엔티티(Entity)

스푸핑은 ‘속임수’라는 뜻이다.
누군가가 자신을 다른 사람인 것처럼 꾸미는 것을 말한다.

예를 들어, 네 친구인 척하면서
“나는 네 친구야.” 하고 거짓말하는 사람이 있다고 해 보자.
사실은 나쁜 사람인데 겉으로는 친구처럼 보이는 상황이다.

컴퓨터 세계에서는 공격자가 진짜 컴퓨터나 진짜 사람인 것처럼 속이는 것을 스푸핑이라고 부른다.

정리
스푸핑: “나는 네 친구야.” 하고 거짓으로 속이는 행동.

엔티티(Entity)는 어떤 ‘존재, 주체’를 뜻한다.
사람일 수도 있고, 컴퓨터일 수도 있고, 프로그램일 수도 있다.
쉽게 말하면 등장인물이라고 생각하면 된다.

예를 들어 내가 게임을 할 때 캐릭터가 나오잖아.
그 캐릭터도 하나의 엔티티다.
인터넷에서는 서버, 클라이언트, 사용자 같은 것들이 엔티티가 될 수 있다.

정리
엔티티: 인터넷이나 세상 속에서 등장하는 주체(사람, 컴퓨터, 프로그램 등).

---
## 11. 부적절한 인증서 유효성 검증

코드 예제 – SSL 기반 웹 서버 연결
(서버 인증을 제대로 안 하면 생기는 문제) 

다음 예제는 SSL 기반 웹 서버 연결에서,
클라이언트 측에서 통신 대상 서버를 제대로 인증하지 않고 접속하는 모습을 보여준다.

이 경우 서버를 신뢰할 수 없으며,
클라이언트 시스템에 영향을 주는 악성 데이터를 수신할 수밖에 없다.

1. 안전하지 않은 코드 예시

```javascript
const https = require('https')

const getServer = () => {
  const options = {
    hostname: 'dangerous.website',
    port: 443,
    method: 'GET',
    path: '/',
    // 유효하지 않은 인증서를 가지고 있어도 무시하는 옵션이므로 안전하지 않음
    rejectUnauthorized: false
  }

  const req = https.request(options, (response) => {
    console.log('status code =', response.statusCode)
  })

  req.on('error', (e) => {
    console.error('에러 발생 =', e)
  })

  req.end()
}
```

여기서는 `rejectUnauthorized: false` 로 설정해서
인증서가 유효하지 않아도 그냥 통신을 진행해 버린다.
즉, 중간자 공격이나 위장 서버(스푸핑 서버)를 막지 못한다.

2. 안전한 코드 예시

```javascript
const https = require('https')

const getServer = () => {
  const options = {
    hostname: 'dangerous.website',
    port: 443,
    method: 'GET',
    path: '/',
    // 유효하지 않은 인증서는 거절하도록 설정
    rejectUnauthorized: true
  }

  const req = https.request(options, (response) => {
    console.log('status code =', response.statusCode)
  })

  req.on('error', (e) => {
    console.error('에러 발생 =', e)
  })

  req.end()
}
```

여기서는 `rejectUnauthorized: true` 로 설정했기 때문에
인증서가 이상하거나 위조된 서버에 대해서는 연결을 거절한다.

---

## 12. 사용자 하드디스크에 저장되는 쿠키를 통한 정보 노출 

1. 악성코드 유포
2. 사용자 PC 감염
3. 악성코드가 저장된 웹 브라우저 쿠키 파일에 접근해 주요 정보 유출

대부분의 웹 응용 프로그램에서 쿠키는 메모리에 상주하며, 브라우저가 종료되면 사라진다.
하지만 개발자는 브라우저 세션에 관계없이 지속적으로 쿠키 값을 저장하도록 설정할 수 있다.

이 경우 정보는 디스크에 기록되고,
다음 브라우저 세션 시작 시 다시 메모리에 로드된다.

개인정보, 인증정보 등이 이런 영속적인 쿠키(Persistent Cookie)에 저장된다면
공격자는 쿠키에 접근할 기회가 많아지고, 시스템은 더 취약해진다.

정리
세션 쿠키: 브라우저 창을 닫으면 자동으로 사라지는 쿠키.
영속 쿠키: 개발자가 만료 날짜를 설정해, 브라우저를 꺼도 디스크에 남아 있는 쿠키.

예시
Set-Cookie: level=3; Expires=Wed, 31 Dec 2025 23:59:59 GMT; Path=/

1. 안전하지 않은 코드 예시

```javascript
const express = require('express')
const router = express.Router()

router.get("/vuln", (req, res) => {
  // 쿠키의 만료 시간을 1년으로 과도하게 길게 설정하고 있어 안전하지 않다
  res.cookie('rememberme', '1', {
    expires: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000)
  })
  return res.send("쿠키 발급 완료")
})
```

2. 안전한 코드 예시

만료 시간은 해당 기능에 맞춰 ‘최소한’으로 설정하고,
영속적인 쿠키에는 중요 정보가 포함되지 않도록 해야 한다.

HTTPS를 통해서만 쿠키를 전송하도록 `secure` 속성을 true(기본값 false)로 설정할 수 있다.
클라이언트 측에서 JavaScript가 쿠키에 접근하지 못하게 하려면 `httpOnly` 속성을 true로 설정한다.

다음은 쿠키 만료 시간을 1시간으로 설정한 예시이다.

```javascript
const express = require('express')
const router = express.Router()

router.get("/patched", (req, res) => {
  res.cookie('rememberme', '1', {
    expires: new Date(Date.now() + 60 * 60 * 1000), // 1시간
    secure: true,
    httpOnly: true
  })
  return res.send("쿠키 발급 완료")
})
```

쿠키 보안 속성 정리

쿠키는 웹사이트가 컴퓨터에 남겨두는 작은 메모다.
이 메모를 안전하게 지키기 위해 두 가지 중요한 자물쇠가 있다.

1. secure
   HTTPS에서만 쿠키를 보낼 수 있게 하는 속성이다.
   브라우저 요청이 HTTPS일 때만 해당 쿠키를 서버로 전송하고,
   HTTP 요청에는 아예 쿠키를 붙이지 않는다.

2. httpOnly
   브라우저에서 실행되는 JavaScript가 쿠키를 읽거나 수정하지 못하게 막는 속성이다.
   XSS(크로스 사이트 스크립팅) 공격이 성공하더라도
   `document.cookie` 로 쿠키를 빼가기 어렵게 만들어 준다.

예시:

```javascript
console.log(document.cookie)
// "theme=dark; loggedIn=true" 와 같은 형식으로 쿠키들이 한 줄 문자열로 보인다.
```

httpOnly가 설정된 쿠키는 `document.cookie` 에서 보이지 않는다.

---

## 13. 주석문 안에 포함된 시스템 주요 정보 

공격 절차 예시

1. 공격자가 소스코드에 접근
2. 주석 문을 검색
3. 주석 안에서 중요정보(비밀번호, 관리자 계정 등)를 획득

예:

```javascript
// password for administrator is 'tiger'
```

소프트웨어 개발자가 편의를 위해 주석에 패스워드 등을 적어두면,
나중에 소스가 배포된 후 그걸 찾아서 모두 제거하는 것은 매우 어렵다.

만약 공격자가 소스코드에 접근할 수 있다면,
이 정보들을 이용해 시스템에 손쉽게 침입할 수 있다.

1. 안전하지 않은 코드 예시

```javascript
router.post("/vuln", (req, res) => {
  // 주석문에 포함된 중요 시스템의 인증정보
  // id = admin, password = 1234
  const result = login(req.body.id, req.body.password)
  return res.send(result)
})
```

2. 안전한 코드 예시

```javascript
router.post("/vuln", (req, res) => {
  // 주석문에는 민감한 정보를 남기지 않는다.
  const result = login(req.body.id, req.body.password)
  return res.send(result)
})
```

정리
프로그램 개발 시 주석에 남겨 놓은 사용자 계정, 패스워드 등은
개발 완료 후 반드시 제거해야 한다.

---

## 14. 솔트(Salt) 없이 일방향 해시 함수 사용
 

패스워드와 같은 중요정보를 저장할 때는
가변 길이 데이터를 고정된 크기의 해시값으로 변환해 주는
일방향 해시 함수를 이용해 저장할 수 있다.

하지만 중요 정보를 솔트 없이 해시만 사용해 저장한다면,
공격자는 미리 계산된 레인보우 테이블을 이용해 해시값으로부터
원래 비밀번호를 빠르게 찾아낼 수 있다.

레인보우 테이블 비유
비밀번호를 빠르게 맞추려고 만든 커다란 비밀 사전이다.
비밀번호와 그에 대응하는 해시값을 미리 잔뜩 계산해 두고,
나중에 해시값을 보면 바로 원래 비밀번호를 찾아낼 수 있도록 만들어 둔 것이다.

해시 함수란?
가변 길이 데이터를 일정한 길이의 해시값으로 바꾸는 함수이다.
아무리 긴 글자라도 짧고 일정한 길이의 숫자·문자 코드로 바꿔 준다.

비유
긴 편지를 보내도, 우편번호는 항상 짧고 일정한 숫자다.
해시 함수는 이런 식으로 길이가 다른 데이터를 일정한 길이의 코드로 바꿔주는 도장 같은 역할이다.

일방향(One-way) 비유
달걀을 깨서 계란후라이를 만들 수는 있지만,
계란후라이를 다시 원래 달걀로 되돌릴 수는 없다.
해시 함수도 비슷하다.
원래 비밀번호로 해시값을 만드는 것은 가능하지만,
해시값만 보고 원래 비밀번호를 되돌리는 것은 사실상 불가능하다.

솔트(Salt)란?
비밀번호를 해시하기 전에 섞어주는 작은 랜덤 값이다.
감자튀김에 소금을 뿌리면 맛이 달라지듯,
같은 비밀번호라도 소금을 다르게 뿌리면 결과(해시값)가 달라진다.
그래서 여러 사람이 같은 비밀번호를 쓰더라도 저장된 해시값은 서로 달라진다.

예제 코드 – 솔트를 사용하는 해시 함수

```javascript
const crypto = require('crypto')

function getHashFromPwd(pw) {
  // 솔트 값을 사용하면 길이가 짧은 패스워드라도 고강도의 해시를 생성할 수 있다.
  // 솔트 값은 사용자별로 유일하게 생성해야 하며, 패스워드와 함께 DB에 저장해야 한다.
  const salt = crypto.randomBytes(16).toString('hex')
  const hash = crypto.createHash('sha256').update(pw + salt).digest('hex')
  return { hash, salt }
}
```

요약
비밀번호를 안전하게 만드는 작은 비밀 도구가 바로 솔트(salt)와 해시(hash)다.

1. 저장할 때

* 비밀번호 + 솔트 → 해시 함수(sha256 등) → 해시값 생성
* DB에는 “해시값 + 솔트”만 저장
* 원래 비밀번호는 절대 저장하지 않는다.

2. 검증할 때

* 사용자가 입력한 비밀번호에 DB에 저장된 솔트를 다시 섞어
  같은 방식으로 해시를 만든다.
* 그 결과가 DB에 저장된 해시와 같으면 비밀번호가 맞는 것이다.

3. 더 안전하게 만들기

* sha256(pw + salt) 만 한 번 쓰는 것보다
  PBKDF2, bcrypt, scrypt, argon2 같은 알고리즘으로
  여러 번 반복해서 갈아버리면(연산 반복) 훨씬 안전하다.
* 반복 연산이 많을수록 공격자가 무차별 대입 공격을 할 때
  훨씬 느려지고 힘들어진다.

정리 키워드
salt: 비밀 양념, 결과를 다르게 만드는 랜덤한 문자열
hash: 되돌릴 수 없게 갈아 만든 복잡한 문자열
목표: 비밀번호를 안전하게 저장하고, 훔쳐봐도 원래 비밀번호를 모르게 만들기

---

## 15. 무결성 검사 없는 코드 다운로드

---

공격 시나리오

1. 호스트 서버 변조 또는 중간자 공격으로 코드 변조
2. 안전하지 않은 다운로드 서버로부터 코드 다운로드
3. 변조된 코드 실행 → 악의적인 코드 실행

원격지에 있는 소스코드나 실행 파일을
무결성 검사 없이 다운로드한 후 그대로 실행하는 프로그램이 종종 있다.

이런 경우,

* 호스트 서버 변조
* DNS 스푸핑(DNS spoofing)
* 전송 중 코드 변조

등의 공격을 통해, 공격자가 악의적인 코드를 실행하게 만들 수 있다.

파일(및 소프트웨어)의 무결성을 확인하는 대표적인 방법은 두 가지다.

1. 암호학적 해시(sha256 등)
2. 디지털 서명(코드 서명, 인증서)

무결성을 보장하기 위해서는 해시를 사용하고,
가능하면 코드 서명 인증서를 사용해 서명과 인증을 확인하는 것이 안전하다.

DNS 스푸핑을 방어할 수 있는 방식의 DNS lookup을 수행하고,
코드 전송 시 신뢰할 수 있는 암호 기법(HTTPS, TLS 등)으로 전송해야 한다.

또한 다운로드한 코드는
작업 수행에 필요한 최소한의 권한으로 실행해야 한다(권한 최소화).

정리

* 소스코드는 신뢰할 수 있는 사이트에서만 다운로드
* 파일의 인증서 또는 해시값을 비교하여 변조 여부 확인
* 무결성 검사 없이 실행하지 않기

---

## 16. 반복된 인증 시도 제한 기능 부재 

공격자 시나리오

* ID와 비밀번호에 대해 무작위 대입(사전 대입, brute force) 공격을 시도
* 일정 시간 내에 여러 번 반복해서 로그인 시도
* 계정 잠금, 추가 인증, CAPTCHA 등 방어가 없다면
  결국 맞는 비밀번호를 찾을 수 있다.

악의적인 사용자의 반복된 인증 시도를
클라이언트 측에서 막을 수도 있지만,
궁극적으로는 서버 측에서 안전한 코드로 인증 시도 횟수를 제한해야 한다.

1. 안전하지 않은 코드 예시

```javascript
const crypto = require('crypto')

router.post("/vuln", (req, res) => {
  const id = req.body.id
  const password = req.body.password

  const hashPassword = crypto.createHash("sha512")
    .update(password)
    .digest("base64")

  const currentHashPassword = getUserPasswordFromDB(id)

  // 인증 시도에 대한 제한이 없어 반복적인 인증 시도가 가능
  if (hashPassword === currentHashPassword) {
    return res.send("login success")
  } else {
    return res.send("login fail")
  }
})
```

2. 안전한 코드 예시

```javascript
const crypto = require('crypto')
const LOGIN_TRY_LIMIT = 5

router.post("/patched", (req, res) => {
  const id = req.body.id
  const password = req.body.password

  // 로그인 실패 기록 가져오기
  const loginFailCount = getUserFailCount(id)

  // 로그인 실패 횟수 초과로 인해 잠금된 계정에 대한 인증 시도 제한
  if (loginFailCount >= LOGIN_TRY_LIMIT) {
    return res.send("account lock (too many failed)")
  }

  const hashPassword = crypto.createHash("sha512")
    .update(password)
    .digest("base64")
  // 실제로는 솔트를 사용하는 것이 더 안전하지만 예제에서는 단순화

  const currentHashPassword = getUserPasswordFromDB(id)

  if (hashPassword === currentHashPassword) {
    deleteUserLoginFailCount(id)
    return res.send("login success")
  } else {
    updateUserFailCount(id)
    return res.send("login fail")
  }
})
```

정리

* 최대 인증 시도 횟수를 제한
* 일정 횟수 이상 실패 시 계정 잠금 또는 추가 인증 절차(OTP, 이메일 인증 등) 요구
* CAPTCHA, 2FA(Two-Factor Authentication) 도입 고려

---

# 제3절 시간 및 상태

동시 또는 거의 동시에 여러 코드 수행을 지원하는 병렬 시스템이나,
하나 이상의 프로세스가 동작하는 환경에서
시간 및 상태를 부적절하게 관리할 때 발생할 수 있는 보안 약점이다.

## 1. 종료되지 않는 반복문 또는 재귀 함수
   종료 조건이 없는 반복문이나 재귀 함수는
   CPU와 메모리 같은 자원을 계속 사용하여 자원 고갈을 일으킬 수 있다.
   (Func_A() → 자원 고갈 같은 상황)
 
---
# 제5절 코드오류 

## 3. 신뢰할 수 없는 데이터의 역질렬화

HMAC 검증 예시
 

취약한 코드 예시
사용자로부터 넘어온 직렬화 데이터를 그대로 JSON.parse 해서 쓰는 경우

```javascript
const express = require('express')
const app = express()

// 취약한 버전 (HMAC 검증 없음)
function load_user_object(req, res) {
  const serializedData = req.query.data
  // 사용자로부터 입력받은 알 수 없는 데이터를 그대로 역직렬화
  const user = JSON.parse(serializedData)
  return res.send({ user: user, isAdmin: user.isAdmin })
}

app.get('/vuln', (req, res) => load_user_object(req, res))
```

위 코드는

* data 안에 뭐가 들어있는지 검증 없이 그대로 JSON.parse
* user.isAdmin 같은 필드도 사용자가 마음대로 조작 가능
  이런 문제가 있다.

안전한 코드 예시 (HMAC으로 변조 여부를 검증한 뒤 역직렬화)

```javascript
const express = require('express')
const crypto = require('crypto')
const app = express()

function load_user_object_safe(req, res) {
  const serializedData = req.query.data

  // 전체 body 구조: { userInfo: {...}, hashed: '...' } 라고 가정
  const body = JSON.parse(serializedData)

  // 데이터 변조를 확인하기 위한 해시값
  const hashedMac = body.hashed

  // 사용자로부터 입력받은 userInfo 객체만 직렬화
  const userInfo = JSON.stringify(body.userInfo)

  const secretKey = 'secret_key'
  const hmac = crypto.createHmac('sha512', secretKey)

  // 직렬화된 사용자 입력값을 해싱
  hmac.update(userInfo)
  const calculatedHMAC = hmac.digest('hex')

  // 전달받은 해시값 hashedMac 과, 우리가 계산한 해시값 calculatedHMAC 비교
  if (calculatedHMAC === hashedMac) {
    const userObj = JSON.parse(userInfo)
    return res.send(userObj)
  } else {
    console.log('hmac =', calculatedHMAC)
    return res.send('신뢰할 수 없는 데이터입니다')
  }
}

app.get('/patched', (req, res) => load_user_object_safe(req, res))
```

정리
역직렬화된 데이터의 특정 부분만 필요하다면
가능하면 JSON 같은 텍스트 기반 안전한 형식을 쓰고,
필요할 경우 HMAC 등으로 변조 여부를 확인한 뒤 사용한다.

---

# 6절 캡슐화 – 세션/전역 상태 문제
 

정의
중요한 데이터나 기능을 불충분하게 캡슐화하거나, 잘못 사용해서 발생하는 보안 약점이다.
정보 노출, 권한 문제 등으로 이어질 수 있다.

## 1. 잘못된 세션에 의한 데이터 정보 노출

다중 스레드 환경에서는 싱글톤 객체의 필드에 경합 조건이 발생할 수 있다.
따라서 다중 스레드 환경에서는 데이터를 저장하는 전역 변수를 사용하지 않도록 주의해야 한다.
서로 다른 세션에서 같은 전역 상태를 공유하지 않도록 코드를 작성해야 한다.

안전한 코딩 기법
싱글톤 패턴을 사용하는 경우 변수 범위에 특히 주의한다.
다중 스레드 환경에서 클래스 변수의 값은 하위 메소드와 공유되므로,
필요하다면 인스턴스 변수로 선언해서 세션별로 분리해야 한다.

서버 라우터 코드에서 전역 변수를 사용하면
서로 다른 세션 간에 데이터가 공유되어 의도하지 않은 데이터가 전달될 수 있다.

취약한 코드 예시

```javascript
let instance

class UserSingleton {
  constructor() {
    this.userName = 'testUser'
    if (instance) {
      return instance
    }
    instance = this
  }

  getUserProfile() {
    return this.userName
  }
}

router.get("/vuln", (req, res) => {
  const user = new UserSingleton()
  const profile = user.getUserProfile()
  // 서로 다른 세션에서 공유되는 값을 사용하는 경우,
  // 다른 세션에 의해 데이터가 노출될 수 있음
  return res.send(profile)
})
```

위 경우
UserSingleton 의 인스턴스가 하나만 존재하기 때문에
여러 사용자가 동시에 접근할 때, 같은 userName 을 공유하게 된다.

안전한 코드 예시

공유가 금지된 변수는 싱글톤 패턴이 아닌 일반 클래스 안에 선언해
세션 간에 공유되지 않도록 한다.

```javascript
class User {
  constructor() {
    this.userName = 'testUser'
  }

  getUserProfile() {
    return this.userName
  }
}

router.get("/patched", (req, res) => {
  const user = new User()
  const profile = user.getUserProfile()
  // 서로 다른 세션에서 공유되지 않는 클래스 정의를 사용하기 때문에 안전
  return res.send(profile)
})
```

---

## 2. 제거되지 않고 남은 디버그 코드

---

디버깅 목적으로 삽입된 코드는 개발이 완료되면 제거해야 한다.
디버그 코드는 설정 등 민감한 정보나,
의도하지 않은 시스템 제어로 이어지는 정보가 포함될 수 있다.

만약 디버그 코드가 남아 있는 채로 배포되면,
공격자가 이를 통해 내부 상태를 추적하거나
특정 로직을 우회할 수 있다.

자바스크립트에서 일반적으로 console.log, console.error 로 디버그 메시지를 출력한다.

안전한 코딩 기법
소프트웨어 배포 전에 반드시 디버그 코드를 확인 후 삭제한다.
코드 에디터에서 console.log, console.error 를 일괄 검색해서 삭제하거나,
배포 모드에서는 console.log 가 동작하지 않도록 덮어쓰는 방법을 사용할 수 있다.

React 예시

개발이 끝난 코드에서, 혹시 남아 있을 로그를 막기 위해
애플리케이션 진입 코드(예: index.js)에 다음 코드를 추가할 수 있다.

```javascript
if (process.env.NODE_ENV === 'production' && typeof window !== 'undefined') {
  console.log = () => {}
}
```

이렇게 하면 프로덕션 모드에서는
코드 내부에 남은 모든 console.log 호출이 있어도 실제로 출력되지 않는다.

Express 예시

마찬가지로 서버 진입 코드(index.js)에서 다음과 같이 설정할 수 있다.

```javascript
app.listen(80, () => {
  if (!process.env.DEBUG) {
    console.log = function () {}
  }
})
```

DEBUG 환경 변수가 없는 상태에서는
console.log 를 빈 함수로 덮어써 로그가 찍히지 않도록 한다.

---

## 3. public 메소드에서 private 배열 반환

---

상황
public 메소드에서 private 배열(또는 객체)을 그대로 반환하면
그 배열의 참조(주소)가 외부로 노출된다.
외부에서 배열을 수정하면 내부 private 데이터도 같이 변경된다.

자바스크립트 클래스 배경
ES6 이전에는 프로토타입 방식으로 클래스를 흉내냈고,
private 를 언더스코어(_name) 같은 컨벤션으로 표현했다.
이후 ES2022 등에서 #필드를 사용해 private 속성을 지원하게 되었다.

안전한 코딩 기법
private 로 선언된 배열을 public 메소드로 직접 반환하지 않는다.
반환이 필요하면 복사본을 만들어서 반환하고,
그 안의 원소도 Object.assign 등으로 한 번 더 복사해 원본 보호를 강화한다.

취약한 코드 예시

```javascript
class UserObj {
  #privArray = []

  // private 배열을 그대로 리턴하는 public 메소드 사용 → 취약
  get_private_member = () => {
    return this.#privArray
  }
}
```

위 경우
외부에서 get_private_member 로 받은 배열을 수정하면
내부 #privArray 도 함께 수정된다.

안전한 코드 예시

```javascript
class UserObj {
  #privArray = []

  // private 배열을 반환할 때 복사본을 만들어 리턴
  get_private_member = () => {
    const copied = Object.assign([], this.#privArray)
    return copied
  }
}
```

이렇게 하면
외부에서 copied 배열을 변경해도
내부의 #privArray 는 그대로 유지된다.

---

## 4. private 배열에 public 데이터 할당

---

상황
public 메소드의 인자를 private 배열에 그대로 저장하면,
그 인자가 참조 타입(배열, 객체)인 경우
외부에서 인자를 수정하는 것만으로 private 배열 내용을 바꿀 수 있다.

안전한 코딩 기법
public 메소드의 인자를 private 배열에 그대로 대입하지 않는다.
필요하다면 값 복사를 하거나,
별도의 public 필드나 로컬 변수에 저장하게 설계한다.

취약한 코드 예시

```javascript
class UserObj {
  #privArray = []

  // private 배열에 외부 값을 바로 대입하는 경우 취약
  set_private_member = (input_list) => {
    this.#privArray = input_list
  }
}
```

안전한 코드 예시 (외부 값을 private 아닌 다른 필드에 저장)

```javascript
class UserObj2 {
  #privArray = []

  // 사용자가 전달한 값을 private가 아닌 public 필드에 저장
  set_private_member = (input_list) => {
    this.userInput = input_list
  }
}
```

또는 정말 private 에 저장해야 한다면
input_list 의 복사본을 만들어서 할당해야 한다.

예)

```javascript
set_private_member = (input_list) => {
  this.#privArray = Array.isArray(input_list)
    ? input_list.slice()
    : []
}
```

---

# 제7절 API 오용 – DNS lookup과 취약한 패키지 

정의
의도된 사용과 다르게 API를 사용하거나,
보안에 취약한 API를 사용해서 발생하는 보안 약점을 말한다.

## 1. DNS lookup 에 의존한 보안 결정

공격 아이디어
공격자가 DNS 엔트리를 조작해
[www.bank.kr](http://www.bank.kr) 같은 도메인이 가리키는 IP를 바꿔버릴 수 있다.

이 경우 사용자는 도메인 이름만 보고
정상 은행 사이트라고 믿고 접속하지만,
실제로는 위장 웹 서버로 연결될 수 있다.

따라서
도메인 이름만 믿고 인증, 접근 통제를 결정하면 안 된다.

안전한 코딩 기법
보안 결정(인증, 인가 등)에 도메인 이름 기반 DNS lookup 결과를 직접 사용하지 않는다.
필요하다면 신뢰하는 IP 목록을 가지고 비교하는 식으로 처리한다.

취약한 코드 예시

```javascript
const dns = require("dns")

router.get("/vuln", (req, res) => {
  let trusted = false
  const trustedHost = "www.google.com"
  const hostName = req.query.host

  // 공격자가 DNS를 조작해도 hostName 문자열만 맞으면 trusted 로 처리됨 → 취약
  if (hostName === trustedHost) {
    trusted = true
  }

  return res.send({ trusted })
})
```

안전한 코드 예시 (IP 주소 비교)

```javascript
const dns = require("dns")

router.get("/patched", async (req, res) => {
  let trusted = false
  const trustedIp = "142.250.207.100" // 예: 실제 서버의 IP 주소

  async function dnsLookup() {
    return new Promise((resolve, reject) => {
      dns.lookup(req.query.host, 4, (err, address, family) => {
        if (err) return reject(err)
        resolve(address)
      })
    })
  }

  try {
    const resolvedIp = await dnsLookup()
    if (resolvedIp === trustedIp) {
      trusted = true
    }
  } catch (e) {
    // 에러 시 trusted 는 그대로 false
  }

  return res.send({ trusted })
})
```

요점
보안 결정에 도메인 문자열을 그대로 쓰지 말고,
검증된 IP나 별도의 신뢰 메커니즘을 사용한다.

## 2. 취약한 API / 취약한 패키지 사용

npm, yarn 으로 설치한 자바스크립트 패키지는
누군가가 만들어 올린 코드이다.

문제점

1. 사용자 배포 패키지 내부의 결함

   * 의도치 않은 버그나 보안 약점
   * 일부러 악성코드를 심어 놓을 수도 있음

2. 언어 엔진 자체의 결함

   * Node.js 엔진, V8 엔진 같은 내부에서 보안 취약점이 발견될 수 있음

이런 취약점들이 있으면

* 특정 함수에 조작된 데이터를 넣었을 때
* 예상치 못한 실행, 정보 노출, 권한 상승 등이 발생할 수 있다.

완화 방안

1. 취약한 패키지를 사용하지 않는다.

   * 공식 보안 공지, 취약점 DB, GitHub security advisory 등 확인
2. 취약한 버전을 사용하지 않는다.

   * 버전 업그레이드, npm audit, yarn audit 등 활용
3. 외부 입력값을 패키지 함수에 넣기 전 검증, 필터링, 인코딩 등의 보호 루틴 적용
4. 언어 엔진(Node.js) 자체의 결함인 경우

   * 취약점이 패치된 버전으로 업그레이드한다.

정리

* 외부 패키지는 항상 신뢰할 수 없는 코드라고 보고 사용할 것
* 취약점 보고와 보안 공지를 주기적으로 확인할 것
* Node.js, 라이브러리, 프레임워크 모두 최신 보안 패치를 유지할 것

--- 
# 부록
## 제 1절 구현 단계 보안약점 제거 기준

1. 입력 데이터 검증 및 표현

1) SQL 삽입
   SQL 질의문을 생성할 때 검증되지 않은 외부 입력값을 허용하면, 악의적인 질의문이 실행될 수 있는 보안 약점이다.

2) 코드 삽입
   프로세스가 외부 입력값을 코드(명령어)로 해석하여 실행할 수 있을 때, 검증되지 않은 입력이 악의적인 코드 실행으로 이어질 수 있는 보안 약점이다.

3) 경로 조작 및 자원 삽입
   시스템 자원 접근 경로나 자원 제어 명령어에 대해 입력 데이터를 검증하지 않으면, 외부에서 시스템 자원에 무단 접근하거나 공격이 가능해지는 보안 약점이다.

4) 크로스 사이트 스크립트(XSS)
   사용자 브라우저에서 실행되는 스크립트에 검증되지 않은 입력값이 포함되면, 악의적인 스크립트가 실행될 수 있는 보안 약점이다.

5) 운영체제 명령어 삽입
   운영체제 명령어를 생성할 때 검증되지 않은 입력값을 허용하면 악의적인 명령어가 실행될 수 있는 보안 약점이다.

6) 위험한 형식의 파일 업로드
   파일 확장자나 파일 형식 검증 없이 업로드를 허용하면, 악성 파일 업로드를 통한 공격이 가능해지는 보안 약점이다.

7) 신뢰되지 않은 URL 주소로 자동 접속
   URL 링크 생성 시 입력값을 검증하지 않으면, 사용자를 악성 사이트로 자동 접속시키는 보안 약점이 발생한다.

8) 부적절한 XML 외부 개체 참조(XXE)
   조작된 XML 외부 개체에 대한 검증 없이 참조를 허용하면 공격이 가능한 보안 약점이다.

9) XML 삽입
   XQuery, XPath 질의문을 생성할 때 검증되지 않은 입력값을 허용하면 악의적인 질의문이 실행될 수 있다.

10) LDAP 삽입
    LDAP 명령문을 만들 때 입력값 검증을 하지 않으면, 악의적인 질의문 실행이 가능한 보안 약점이다.

11) 서버사이드 요청 위조(SSRF)
    서버 간 요청을 처리할 때 입력값 검증이 없으면, 공격자가 임의의 서버로 요청을 보내거나 조작할 수 있는 보안 약점이다.

12) HTTP 응답 분할
    HTTP 응답 헤더에 개행 문자(CR/LF)를 포함한 검증되지 않은 입력을 허용하면 악의적인 코드가 실행될 수 있는 보안 약점이다.

13) 정수형 오버플로우
    정수형 변수 값이 허용 범위를 벗어나면 프로그램이 비정상 동작하는 보안 약점이다.

14) 보안 기능 결정에 사용되는 부적절한 입력값
    인증 또는 권한 부여 결정에 대해 검증되지 않은 입력값을 허용하면 보안 기능 우회가 가능한 보안 약점이다.

15) 메모리 버퍼 오버플로우
    메모리 버퍼의 경계값을 넘어서 데이터가 저장되면 예상치 못한 오류와 공격이 발생할 수 있다.

16) 포맷 스트링 삽입
    printf, format 같은 문자열 포맷 함수에 외부 입력값을 그대로 사용하면 발생하는 보안 약점이다.

---

2. 보안 기능

1) 적절한 인증 없이 중요 기능 허용
   중요 정보를 인증 없이 조회하거나 수정할 수 있으면 발생하는 보안 약점이다.

2) 부적절한 인가
   중요 자원 접근에 적절한 권한 제어가 없으면 비인가 사용자가 접근할 수 있다.

3) 중요 자원에 대한 잘못된 권한 설정
   중요 자원에 접근 권한을 잘못 부여하여 중요 정보가 노출되거나 수정될 수 있다.

4) 취약한 암호화 알고리즘 사용
   기밀성을 보장할 수 없는 알고리즘 사용 시, 중요 정보가 노출될 수 있다.

5) 암호화되지 않은 중요 정보
   전송 또는 저장 시 암호화하지 않으면 정보가 노출될 수 있다.

6) 하드코드된 중요 정보
   암호화 키 또는 비밀번호를 소스코드에 작성하면 유출 위험이 매우 크다.

7) 충분하지 않은 암호 키 길이
   키 길이가 짧으면 암호가 쉽게 풀리고 정보 보호가 불가능하다.

8) 적절하지 않은 난수 값 사용
   예측 가능한 난수는 공격자가 다음 값을 예측하고 시스템을 공격하도록 만든다.

9) 취약한 패스워드 허용
   규칙(대문자/숫자/특수문자 길이 등)이 약하면 쉽게 노출될 수 있다.

10) 부적절한 전자서명 검증
    전자서명 검증이 부적절하면 악성 코드가 실행될 수 있다.

11) 부적절한 인증서 유효성 검증
    유효期限 또는 도메인 정보를 검증하지 않으면 공격에 취약하다.

12) 쿠키 저장에 의한 정보 노출
    쿠키에 중요한 정보를 저장하면 유출될 수 있다.

13) 주석문 안의 중요 정보
    주석에 인증 자료 등이 포함되면 소스코드 노출 시 함께 노출된다.

14) 솔트 없는 일방향 해시 사용
    레인보우 테이블 공격으로 원본이 복원될 수 있다.

15) 무결성 검사 없는 코드 다운로드
    검증되지 않은 실행 파일 다운로드 시 악성 코드가 실행될 수 있다.

16) 인증 시도 횟수 제한 부재
    인증 오류 횟수 제한이 없으면 무차별 암호 대입 공격이 가능하다.

---
3. 시간 및 상태

1) 경쟁 조건
   검사 시점과 사용 시점이 달라 발생하는 보안 약점이다.

2) 종료되지 않는 반복문 또는 재귀
   무한 실행으로 시스템 장애가 발생한다.

---

4. 에러 처리

1) 오류 메시지 정보 노출
   오류 메시지에 내부 구조와 민감 정보가 포함되어 노출된다.

2) 오류 상황 대응 부재
   오류 처리 코드가 없으면 시스템이 중단될 수 있다.

3) 부적절한 예외 처리
   예외를 잘못 처리하면 의도하지 않은 동작이 발생한다.

---

5. 코드 오류

1) Null Pointer 역참조
   Null 객체 참조 시 오류가 발생한다.

2) 부적절한 자원 해제
   자원 해제 누락 시 시스템이 자원 부족 상태가 된다.

3) 해제된 자원 사용
   이미 해제된 자원을 사용하면 오류가 발생한다.

4) 초기화되지 않은 변수 사용
   초기화되지 않은 변수를 사용하면 예기치 않은 결과가 발생한다.

5) 신뢰할 수 없는 데이터의 역직렬화
   직렬화 데이터를 검증 없이 역직렬화하면 악성 코드가 실행될 수 있다.

---

6. 캡슐화

1) 잘못된 세션에 의한 데이터 노출
   세션 구분 실패로 중요 정보가 노출될 수 있다.

2) 제거되지 않은 디버그 코드
   디버깅 코드가 노출되면 중요한 정보가 유출될 수 있다.

3) public 메소드에서 private 배열 반환
   private 배열의 주소가 외부로 노출되어 수정될 수 있다.

4) private 배열에 public 데이터 저장
   외부 입력이 private 배열에 저장되면 변조될 수 있다.

---

7. API 오용

1) DNS Lookup에 의존한 보안 결정
   DNS 정보 변조로 공격자가 원하는 서버로 유도할 수 있다.

2) 취약한 API 사용
   취약한 함수나 패키지를 사용하면 예기치 않은 악성 동작이 발생할 수 있다.

---

### 제 2절 용어 정리

AES (Advanced Encryption Standard)
미국 정부 표준 블록 암호 알고리즘. DES를 대체한다.

DES (Data Encryption Standard)
대칭키 암호 방식. 64비트 키 사용. 전수 공격에 취약하다.

HMAC (Hashed-based Message Authentication Code)
해시와 비밀키를 이용한 메시지 인증 방식이다.

HTTPS (Hypertext Transfer Protocol over SSL)
HTTP의 보안을 강화한 프로토콜이다.

LDAP (Lightweight Directory Access Protocol)
TCP/IP 기반 디렉토리 서비스 접근 프로토콜이다.

SHA (Secure Hash Algorithm)
MD5의 취약점을 보완한 해시 알고리즘이다.

MHTML
웹페이지 전체를 하나의 파일로 저장하는 형식(MHT/MHTML).
오프라인 열람과 보관 용도.

SHTML
서버 사이드 인클루드(SSI)를 지원하는 HTML 파일.
서버가 HTML을 보내기 전 동적 처리 작업을 수행한다.

---
 

