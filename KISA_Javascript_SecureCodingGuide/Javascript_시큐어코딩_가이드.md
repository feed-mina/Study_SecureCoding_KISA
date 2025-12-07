아래는 요청대로
오타를 최대한 자연스럽게 수정하고
문장이 끝날 때마다 줄바꿈한 버전이다.
(내용 의미는 그대로 유지, 줄바꿈 정리 위주)

---

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

---

코드 입력
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

3. 경로 조작
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

ORM 사용 예제
express.js에서 많이 사용하는 Sequelize ORM은 인자화된 쿼리 방식을 사용하므로 SQL 삽입 공격으로부터 안전하다.
원시 SQL을 사용할 경우에도 바인딩 변수를 통해 입력값을 전달해야 한다.
 