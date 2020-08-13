#

## PreReq

- JDK >= 12+
- Maven >= 3.6+

## Quick Start

```bash
# Copy example web.xml
cp WebContent/WEB-INF/web.xml.example WebContent/WEB-INF/web.xml

# Update web.xml tie to Okta tenant
vi web.xml
...

mvn clean install
```

Attach to Tomcat.
