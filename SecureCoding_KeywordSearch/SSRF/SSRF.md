# 서버 측 요청 위조 공격(SSRF, Server-Side Request Forgery)

## 서버 측 요청 위조 공격이란
**서버 측 요청 위조 공격**에서는 **공격자가 서버의 기능을 악용하여 내부 리소스를 읽거나 업데이트** 할 수 있다. 공격자는 **서버에서 실행되는 코드가 데이터를 읽거나 전송할 URL을 제공하거나 수정**할 수 있다.
URL을 신중하게 선택하지 않으면 **AWS 메타데이터 같은 서버 구성 정보**를 읽을 수 있다. 또는 **HTTP가 활성화된 데이터베이스 같은 내부 서비스에 연결**할 수도 있다. 또 **외부에 노출되어서는 안 되는 내부 서비스로 POST 요청**을 보낼 수도 있다.
대상 애플리케이션은 **URL에서 데이터를 가져오거나, URL에 데이터를 게시**하거나, **변조될 수 있는 URL에서 데이터를 읽는 기능을 포함**할 수 있다.
공격자는 **완전히 다른 URL을 제공**하거나, **URL 구성 방식이나 경로 탐색(Path Traversal) 등을 조작**하여 이러한 기능 호출을 변경한다.
조작된 요청이 서버로 전송되면, **서버 측 코드는 조작된 URL을 수신하고 해당 URL에서 데이터를 읽으려고 시도**한다.공격자는 **대상 URL을 선택**함으로써 **인터넷에 직접 노출되지 않은 서비스에서 데이터를 읽어낼 수 있다.**

---

### 클라우드 서버 메타데이터의 예시
**AWS 같은 클라우드 서비스**는 **`http://169.254.169.254/` 를 통해 중요한 구성 정보**, 경우에 따라 **인증 키까지 추출될 수 있는 REST 인터페이스를 제공**한다.

---

### 데이터베이스의 HTTP 인터페이스 사례 
**MongoDB 같은 NoSQL 데이터베이스는 HTTP 포트를 통해 REST 인터페이스를 제공**할 수 있다. 데이터베이스 접근이 **내부적으로만 허용되는 경우 인증이 비활성화**되어 있을 수 있다. 
이 경우 공격자는 이를 통해 **데이터를 추출**할 수 있다.

---

### 내부 REST 인터페이스 파일 접근 사례

**공격자는 `file://` URI를 사용**하여 **파일을 읽을 수 있는 가능성**이 있다.
공격자는 이 기능을 이용해 **신뢰할 수 없는 데이터**를, **신뢰할 수 있는 소스에서만 데이터를 읽도록 설계된 코드**로 가져와 **입력 유효성 검사를 우회**할 수도 있다.

---
## OWASP 서버 측 요청 위조 방지 치트시트
* [https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)


위 링크의 치트시트는 **SSRF 공격으로부터 보호하는 방법에 대한 조언**을 제공한다.
문맥에서 **SSRF는 애플리케이션을 악용하여 내부 또는 외부 네트워크, 또는 시스템 자체와 상호작용하는 공격 방식**이다.
이 공격 방식의 **주요 원인** 중 하나는 **URL을 잘못 처리**하는 것이다.
다음 예시에서 이를 확인할 수 있다.
- **외부 서버에 저장된 이미지**(예: 사용자가 아바타 이미지 **URL을 입력하면 애플리케이션이 다운로드**하여 사용한다).
- **사용자 지정 웹훅(Webhook)**(**사용자가 웹훅 핸들러 또는 콜백 URL을 지정**해야 한다).
- 특정 기능을 제공하기 위해 **다른 서비스와 상호작용*하려는 내부 요청**이다.
대부분의 경우 **사용자 데이터가 처리**될 때 함께 전송된다. 이 과정이 제대로 처리되지 않으면 **특정 인젝션 공격이 발생**할 수 있다.
참고로 **SSRF는 HTTP 프로토콜에만 국한되지 않는다.**
일반적으로 첫 번째 요청은 HTTP이지만, 애플리케이션이 두 번째 요청을 수행하는 경우 다른 프로토콜을 사용할 수 있다.
예를 들어 **FTP, SMB(Server Message Block), SMTP(Simple Mail Transfer Protocol)** 등이 있다. 또한 **다른 스키마(schema)**도 사용할 수 있다.
예를 들어 **`file://`, `phar://`, `gopher://`, `data://`, `dict://`** 등이 있다.
애플리케이션이 **XML 외부 엔티티(XXE, XML External Entity) 인젝션에 취약한 경우 SSRF 공격으로 악용**될 수 있다.
사례로, 애플리케이션의 기능과 요구 사항에 따라 **SSRF가 발생할 수 있는 기본적인 경우는 두 가지**이다.
첫째, 애플리케이션이 **식별되고 신뢰할 수 있는 애플리케이션에만 요청을 보낼 수 있는 경우**이다.이 경우는 **허용 목록(Allowlist) 방식을 사용**할 수 있다.
둘째, 애플리케이션이 **외부의 모든 IP 주소 또는 도메인 이름으로 요청을 보낼 수 있는 경우**이다. 이 경우는 허용 목록 방식을 사용할 수 없다. 두 경우는 매우 다르기 때문에, 요약 자료에서는 각각의 방어책을 별도로 설명한다.

---
### 사례 1 애플리케이션이 식별되고 신뢰할 수 있는 애플리케이션에만 요청을 보낼 수 있는 경우
때때로 **애플리케이션은 특정 작업을 수행하기 위해 다른 네트워크에 있는 다른 애플리케이션에 요청을 보내야 한다.**
비즈니스 사례에 따라 **해당 기능이 작동하려면 사용자 입력이 필요할 수 있다.** 예를 들어 사용자의 이름, 성, 생년월일 같은 **개인정보를 입력받아** 내부 인사 시스템에 프로필을 생성하는 웹 애플리케이션을 생각해볼 수 있다.
설계상 이 **웹 애플리케이션은 인사 시스템이 이해할 수 있는 프로토콜을 사용하여 데이터를 처리**한다. 기본적으로 **사용자는 인사 시스템에 직접 접근할 수 없다.** 하지만 사용자 정보를 입력받는 웹 애플리케이션이 SSRF에 취약하다면 사용자는 이를 악용하여 인사 시스템에 접근할 수 있다.
즉 **사용자는 웹 애플리케이션을 인사 시스템의 프록시(Proxy)로 활용**하는 것이다.
**허용 목록 방식**은 **취약한 애플리케이션이 호출하는 내부 애플리케이션이 기술적·비즈니스 흐름에서 명확하게 식별**되므로 실행 가능한 옵션이다. **필요한 호출은 식별되고 신뢰할 수 있는 애플리케이션 간에만** 이루어지도록 설계해야 한다.
이용 가능한 보호 조치는 **애플리케이션 계층과 네트워크 계층에서 모두 적용**할 수 있다.**심층 방어(Defense in Depth) 원칙**을 적용하려면 **두 계층 모두 강화**되어야 한다.

#### 애플리케이션 계층의 보호 조치
애플리케이션 계층에서 **가장 먼저 떠오르는 보호 조치**는 **입력값 유효성 검사**이다.그렇다면 입력 유효성 검사를 어떻게 수행해야 하는가가 핵심이다.
사용되는 **프로그래밍 언어에 따라 URL 파서(Parser)가 악용**될 수 있다. 가능한 대응책 중 하나는 **입력 유효성 검사에 허용 목록 방식을 적용**하는 것이다. 왜냐하면 대부분의 경우 **사용자가 입력하는 정보의 형식은 전역적으로 알려져 있기 때문**이다.
**내부 애플리케이션으로 전송되는 요청**은 다음 정보를 기반으로 할 수 있다. 
```
**비즈니스 데이터가 포함된 문자열, IP 주소(IPv4, IPv6), 도메인 이름, URL**
```

이 문서에서 설명된 **입력 유효성 검사를 우회하는 것을 방지**하려면 **웹 클라이언트에서 리디렉션 후속 실행 지원을 비활성화**해야 한다. 이는 **안전하지 않은 리디렉션(Unsafe Redirect)과 관련된 우회 기법을 줄이기 위함**이다.

SSRF 맥락에서 **입력 문자열이 예상되는 비즈니스 또는 기술 형식을 준수하는지** 확인하기 위해 **유효성 검사를 추가**할 수 있다.
**입력 데이터 형식이 단순한 경우**(예: 토큰, 우편번호 등) **정규표현식을 사용하여 보안 관점에서 데이터 유효성을 검증**할 수 있다.
하지만 **복잡한 형식의 데이터에 대한 정규표현식**은 **유지보수가 어렵고 오류 발생 가능성이 높다.** 따라서 **복잡한 데이터**는 **객체 또는 라이브러리가 제공하는 검증 기능을 사용**하여 유효성 검사를 수행해야 한다.


예시로, **문자열(string) 사용자 입력**이 네트워크와 관련이 없고 **사용자의 개인정보로만 구성**된다고 가정해보자.

---

##### SSRF 관련 유효성 검사 예제 코드

```java
// Regex validation for a data having a simple format
if (Pattern.matches("[a-zA-Z0-9\\s\\-]{1,50}", userInput)) {
    // Continue the processing because the input data is valid
} else {
    // Stop the processing and reject the request
}
```

---

**IP 주소 기반 SSRF 환경**에서는 다음과 같은 **두 가지 유효성 검사를 수행**할 수 있다. 제공된 데이터가 **유효한 IPv4 또는 IPv6 IP 주소인지 확인**한다. **제공된 IP 주소가 식별되고 신뢰할 수 있는 애플리케이션의 IP 주소 중 하나**에 속하는지 확인한다.

**첫 번째 단계의 유효성 검사**는 사용된 기술에 따라 **IP 주소 형식의 보안을 보장하는 라이브러리를 사용**하여 적용할 수 있다.
여기서는 IP 주소 형식 관리를 직접 구현하지 않고, **검증된 유효성 검사 기능을 활용하기 위해 라이브러리 옵션을 제안**한다.
**우회 방법(16진수, 8진수, Dword, URL 및 혼합 인코딩)에 대한 노출과 관련하여 제안된 라이브러리**에 대한 검증이 수행되었다.

* **Java 환경**에서는 **Apache Commons Validator 라이브러리의 InetAddressValidator.isValid 메서드**를 사용한다. 이 메서드는 **16진수, 8진수, Dword, URL 및 혼합 인코딩**을 사용한 우회를 허용하지 않는다. 

.* **NET 환경**에서는 **SDK의 IPAddress.TryParse 메서드**를 사용한다. 이 메서드는 **16진수, 8진수, Dword 및 혼합 인코딩**을 사용하면 **우회가 가능**하다. 하지만 **URL 인코딩으로는 우회할 수 없다.** 여기서는 **허용 목록을 사용**하므로, **허용된 IP 주소 목록과 비교하는 과정에서 모든 우회 시도는 차단**된다.

* **JavaScript 환경**에서는 **ip-address 라이브러리**를 사용한다. 이 라이브러리는 **16진수, 8진수, Dword 및 혼합 인코딩을 사용한 우회**를 허용하지 않는다.
* **Ruby 환경**에서는 **SDK의 IPAddr 클래스**를 사용한다. 이 클래스 역시 **16진수, 8진수, Dword 및 혼합 인코딩**을 사용한 우회를 허용하지 않는다. 해당 메서드 또는 라이브러리의 출력값을 IP 주소로 사용하여 허용 목록과 비교한다.

**수신된 IP 주소의 유효성을 확인**한 후 **두 번째 유효성 검사 단계를 수행**한다.
**식별되고 신뢰할 수 있는 애플리케이션**의 **모든 IP 주소(v4 및 v6 포함)를 파악**한 후 **허용 목록을 생성**한다.
**유효한 IP 주소**는 **해당 목록과 대조**하여 **내부 애플리케이션과의 통신이 가능한지 확인**한다.
이 비교는 **대소문자를 구분하는 엄격한 문자열 비교로 수행**한다.
---

**도메인 이름 검증**을 위해 **DNS 확인을 수행**하여 **도메인의 존재 여부를 확인하는 것은 일반적**이다. 일반적으로 이는 나쁜 방법은 아니지만, 도메인 이름 확인에 사용되는 **DNS 서버 구성에 따라 애플리케이션이 공격에 취약**해질 수 있다.

이 과정에서 **외부 DNS 해석기에 정보가 노출**될 수 있다. 공격자는 이를 이용하여 **합법적인 도메인 이름**을 **내부 IP 주소에 연결**할 수 있다. 이는 **DNS Pinning 공격**으로 알려져 있다.

**공격자**는 **내부 DNS 해석기와 애플리케이션**이 **DNS 통신을 처리**하는 데 사용하는 **API (SDK 또는 타사 라이브러리)에 악성 페이로드를 전달**한 뒤, 이 구성 요소 중 하나의 **취약점을 악용** 할 수 있다.
SSRF 서버 사이드 공격 맥락에서 **도메인에 대해 수행해야 할 유효성 검사는 두 가지**이다.

1_ 제공된 데이터가 유효한 도메인 이름인지 확인한다.
2_ 제공된 도메인 이름이 식별 가능한 애플리케이션의 도메인 허용 목록에 포함되어 있는지 확인한다.

IP 주소 유효성 검사와 유사하게, 첫 번째 단계의 도메인 유효성 검사는 검증된 라이브러리를 사용하여 적용한다. 여기서는 도메인 형식 관리를 직접 구현하지 않고 검증된 유효성 검사 기능을 활용하기 위해 라이브러리 옵션을 제안한다.

제안된 라이브러리는 **DNS 확인 쿼리를 수행하지 않는지 검증**해야 한다. 

* **Java 환경**에서는 **Apache Commons Validator 라이브러리의 DomainValidator.isValid 메서드**를 사용한다.
* **.NET 환경**에서는 **SDK의 Uri.CheckHostName 메서드**를 사용한다.
* **JavaScript 환경**에서는 **is-valid-domain 라이브러리**를 사용한다.
* **Python 환경**에서는 **validators.domain 모듈**을 사용한다.
* **Ruby 환경에** 에서는 적절한 검증 라이브러리를 찾기 어렵다. domainator, public_suffix, addressable 라이브러리를 테스트했지만, 모두 `<script>alert(1)</script>.owasp.org` 를 유효한 도메인으로 판단했다. 따라서 **정규표현식을 사용한 검증**이 제안된다.
**Ruby 정규표현식 예제**이다.

```ruby
domain_names = [
  "owasp.org",
  "owasp-test.org",
  "doc-test.owasp.org",
  "doc.owasp.org",
  "<script>alert(1)</script>",
  "<script>alert(1)</script>.owasp.org"
]

domain_names.each do |domain_name|
  if domain_name =~ /^(((?!-))(xn--|_{1,1})?[a-z0-9-]{0,61}[a-z0-9]{1,1}\.)*(xn--)?([a-z0-9][a-z0-9-]{0,60}|[a-z0-9-]{1,30}\.[a-z]{2,})$/
    puts "[i] #{domain_name} is VALID"
  else
    puts "[!] #{domain_name} is INVALID"
  end
end
```

실행 결과는 다음과 같다.

```text
[i] owasp.org is VALID
[i] owasp-test.org is VALID
[i] doc-test.owasp.org is VALID
[i] doc.owasp.org is VALID
[!] <script>alert(1)</script> is INVALID
[!] <script>alert(1)</script>.owasp.org is INVALID
```
         

**DNS Pinning 공격**에 여전히 취약한 경우, **비즈니스 코드가 실행되는 시점**에서 **실제 DNS 확인이 수행**된다. 
이를 방지하기 위해 **다음과 같은 추가 조치를 적용**해야 한다. 조직에 속한 도메인은 **DNS 해석자 체인**에서 먼저 내부 DNS 서버를 통해 확인하도록 한다.

도메인 허용 목록을 모니터링하여 다음과 같은 경우를 탐지한다.

로컬 IP 주소(v4 및 v6)로 해석되는 경우

조직에 속하지 않는 도메인이 내부 IP 주소(사설 IP 대역)로 해석되는 경우

---

Python3 DNS 검증 스크립트 예제이다.

```python
# Dependencies:
# pip install ipaddress dnspython

import ipaddress
import dns.resolver

# Configure the allowlist of domains
DOMAINS_ALLOWLIST = ["owasp.org", "labslinux"]

# Configure the DNS resolver
DNS_RESOLVER = dns.resolver.Resolver()
DNS_RESOLVER.nameservers = ["1.1.1.1"]

def verify_dns_records(domain, records, record_type):
    error_detected = False
    if records is not None:
        for record in records:
            value = record.to_text().strip()
            try:
                ip = ipaddress.ip_address(value)
                if not ip.is_global:
                    print(
                        "[!] DNS record type '%s' for domain '%s' resolves to a non-public IP '%s'"
                        % (record_type, domain, value)
                    )
                    error_detected = True
            except ValueError:
                print("[!] '%s' is not a valid IP address" % value)
                error_detected = True
    return error_detected

def check():
    error_detected = False
    for domain in DOMAINS_ALLOWLIST:
        try:
            ip_v4_records = DNS_RESOLVER.query(domain, "A")
        except Exception as e:
            ip_v4_records = None
            print("[i] Cannot get A record for domain '%s': %s" % (domain, e))

        try:
            ip_v6_records = DNS_RESOLVER.query(domain, "AAAA")
        except Exception as e:
            ip_v6_records = None
            print("[i] Cannot get AAAA record for domain '%s': %s" % (domain, e))

        if (
            verify_dns_records(domain, ip_v4_records, "A")
            or verify_dns_records(domain, ip_v6_records, "AAAA")
        ):
            error_detected = True

    return error_detected

if __name__ == "__main__":
    if check():
        exit(1)
    else:
        exit(0)
```

---

사용자가 완전한 URL을 입력하는 것을 허용해서는 안 된다.

URL은 유효성 검사가 어렵고,
사용된 기술에 따라 URL 파서가 악용될 수 있다.

네트워크 관련 정보가 필요한 경우에는
유효한 IP 주소 또는 도메인 이름만 허용해야 한다.

---

네트워크 계층 보안의 목적은
취약한 애플리케이션이 임의의 애플리케이션에 요청을 보내는 것을 방지하는 것이다.

애플리케이션은 허용된 경로만 사용하여
통신이 필요한 애플리케이션에만 접근할 수 있어야 한다.

이를 위해 방화벽 구성 요소를 사용하여
허용된 트래픽 흐름만 정의한다.

방화벽 설정을 통해 애플리케이션 접근을 제한함으로써
SSRF 취약점의 영향을 최소화할 수 있다.

---

네트워크 분리는 네트워크 수준에서 불법적인 통신을 직접 차단할 수 있으므로 강력히 권장된다.

---

사례 2는 애플리케이션이 모든 외부 IP 주소 또는 도메인 이름으로 요청을 보낼 수 있는 경우이다.

이 경우 사용자가 외부 리소스의 URL을 제어할 수 있으며,
애플리케이션이 해당 URL로 요청을 보낼 때 문제가 발생한다.

웹훅(Webhook)과 같은 구조가 이에 해당한다.

이 경우 IP 또는 도메인 목록이 사전에 알려지지 않고 동적으로 변경되므로
허용 목록을 사용할 수 없다.

여기서 외부란 내부 네트워크에 속하지 않고
공용 인터넷을 통해 접근해야 하는 모든 IP 주소를 의미한다.

---

이 시나리오에서는 차단 목록 방식이 최선의 선택이다.

허용 목록 방식은 비즈니스 요구사항상 적용하기 어렵다.

차단 목록 방식은 애플리케이션에게
무엇을 해서는 안 되는지를 명확히 알려준다.

---

애플리케이션 계층 보호 조치에서는
요청 대상 애플리케이션이 임의의 토큰을 생성하도록 한다.

이 토큰은 예를 들어 20자 이내의 영숫자로 구성된다.

이 매개변수의 이름은 애플리케이션 내부에서 정의해야 한다.

허용되는 문자는 `[a-z]{1,10}` 과 같이 제한한다.

수신 엔드포인트는 HTTP POST 요청만 허용해야 한다.
