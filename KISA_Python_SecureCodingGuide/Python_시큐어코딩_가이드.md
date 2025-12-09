제 1장 파이썬 시큐어코딩 가이드 KISA
제 1절 배경

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

**‘소프트웨어 개발보안’**은 소프트웨어 개발 과정에서 개발자의 실수와 논리적 오류 등으로 인한 보안 취약점 및 약점들을 최소화해, 사이버 보안 위협으로부터 안전한 소프트웨어를 개발하기 위한 일련의 보안 활동을 의미한다.

- 구체적으로 **소프트웨어 개발 생명주기 SDLC(Software Development Life Cycle)**의 각 단계별로 요구되는 **보안 약점을 초기 단계에서 발견 및 수정**할 수 있으며, 이를 통해 **소프트웨어 운영 중 발생 가능한 잠재적인 보안 취약점을 예방**한다.

소프트웨어 개발보안의 중요성을 이해하고 체계화한 미국의 경우, 국토안보부 DHS를 중심으로 시큐어코딩이 포함된 소프트웨어 개발 전 설계, 구현, 시험 등에 대한 보안 활동 연구를 활발히 진행하고 있다.
이는 2011년 발표된 ‘안전한 사이버 미래를 위한 청사진(Blueprint for a Secure Cyber Future)’에 자세히 언급되어 있다.

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

프로그램 입력값에 대한 검증 누락 또는 부적절한 검증, 데이터의 잘못된 형식 지정, 일관되지 않은 파싱, 인터넷 사용 등으로 인해 보안 약점이 발생할 수 있다.
이는 SQL 삽입, 크로스사이트 스크립트(XSS) 등의 공격을 유발할 수 있다.

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

안전하지 않은 코드 예시

```python
from django.shortcuts import render

def route(request):
    message = request.POST.get('message', '')

    # 외부 입력값을 검증 없이 eval() 함수에 전달하므로 매우 위험하다
    ret = eval(message)

    return render(request, '/success.html', {'data': ret})
```

---

안전한 코드 예시

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

정규 표현식 기반 입력 검증 예시

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

안전하지 않은 코드 예시

```python
from django.shortcuts import render

def request_rest_api(request):
    function_name = request.POST.get('function_name', '')

    # 입력값 검증 없이 실행하면 매우 위험하다
    exec('{}()'.format(function_name))

    return render(request, '/success.html')
```

---

안전한 코드 예시

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
만약 공격자가 ../../../etc/passwd 같은 값을 전달하면 시스템 계정 정보가 담긴 파일의 내용이 노출될 수 있다.

안전하지 않은 코드 예시

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

안전한 코드 예시

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

안전하지 않은 코드 예시

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

안전한 코드 예시

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
 