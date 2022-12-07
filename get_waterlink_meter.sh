#!/bin/bash

USERNAME=            # your water-link username
PASSWORD=            # your water-link password
CLIENT=              # your client id
METER=               # your meter number


STATE=$(echo $RANDOM | md5sum | head -c 32; echo)
C1=$(echo $RANDOM | md5sum | head -c 32; echo)
C2=$(echo $RANDOM | md5sum | head -c 32; echo)
C3=$(echo $RANDOM | md5sum | head -c 32; echo)
CODE_VERIFIER=$(echo $C1$C2$c3)
CODE_CHALLENGE=$(echo -n $CODE_VERIFIER | openssl dgst -binary -sha256 | openssl base64 | tr '/+' '_-' | tr -d '=')
REDIRECT="https://portaaldigitalemeters.water-link.be"

rm /tmp/water.txt

OUTPUT=$(curl  -s -b /tmp/water.txt -c /tmp/water.txt --location "https://a5xhcq3r8.accounts.ondemand.com/oauth2/authorize?client_id=$CLIENT&redirect_uri=$REDIRECT&response_type=code&scope=openid&state=$STATE&code_challenge=$CODE_CHALLENGE&code_challenge_method=S256&response_mode=query")

TOKEN=$(echo $OUTPUT | grep -Po '.*authenticity_token\" value="\K.*?(?=".*)')
XSFR=$(echo $OUTPUT | grep -Po '.*xsrfProtection\" value="\K.*?(?=".*)')
RELAYSTATE=$(echo $OUTPUT | grep -Po '.*State\" value="\K.*?(?=".*)')
SPID=$(echo $OUTPUT | grep -Po ".*spId' type='hidden' value='\K.*?(?=\'.*)")
URL=$(echo $OUTPUT | grep -Po ".*targetUrl' type='hidden' value='\K.*?(?=\'.*)")

RELAYSTATE="client_id=$CLIENT&redirect_uri=https://portaaldigitalemeters.water-link.be&response_type=code&scope=openid&state=$STATE&code_challenge=$CODE_CHALLENGE&code_challenge_method=S256&response_mode=query"
URL="https://a5xhcq3r8.accounts.ondemand.com/oauth2/authorize?client_id=$CLIENT&redirect_uri%3Dhttps%253A%252F%252Fportaaldigitalemeters.water-link.be%26response_type%3Dcode%26scope%3Dopenid%26state%3D$STATE%26code_challenge%3D$CODE_CHALLENGE%26code_challenge_method%3DS256%26response_mode%3Dquery"

OUTPUT=$(curl -s --trace-ascii trace -o /dev/null -D - -b /tmp/water.txt -c /tmp/water.txt  --location https://a5xhcq3r8.accounts.ondemand.com/saml2/idp/sso \
  -H "Accept:text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Host: a5xhcq3r8.accounts.ondemand.com" \
  -H "Origin: https://a5xhcq3r8.accounts.ondemand.com" \
  -H "Referer: https://a5xhcq3r8.accounts.ondemand.com" \
  -H 'authority: portaaldigitalemeters.water-link.be' \
  -H 'accept-language: en-GB,en;q=0.9' \
  -H 'cache-control: max-age=0' \
  -H 'sec-ch-ua: "Not?A_Brand";v="8", "Chromium";v="108", "Google Chrome";v="108"' \
  -H 'sec-ch-ua-mobile: ?0' \
  -H 'sec-ch-ua-platform: "Windows"' \
  -H 'sec-fetch-dest: document' \
  -H 'sec-fetch-mode: navigate' \
  -H 'sec-fetch-site: cross-site' \
  -H 'sec-fetch-user: ?1' \
  -H 'upgrade-insecure-requests: 1' \
  -H 'User-Agent: MOT-V9mm/00.62 UP.Browser/6.2.3.4.c.1.123 (GUI) MMP/2.0' \
  --data "utf8=%E2%9C%93" \
  --data-urlencode "authenticity_token=$TOKEN" \
  --data-urlencode "xsrfProtection=$XSFR" \
  --data-urlencode "method=GET" \
  --data-urlencode "idpSSOEndpoint=https://a5xhcq3r8.accounts.ondemand.com/saml2/idp/sso" \
  --data-urlencode "sp=UC24_PROD" \
  --data-urlencode "RelayState=$RELAYSTATE" \
  --data-urlencode "targetUrl=$URL" \
  --data-urlencode "sourceUrl=" \
  --data-urlencode "org=" \
  --data-urlencode "spId=$SPID" \
  --data-urlencode "spName=UC24_PROD" \
  --data-urlencode "mobileSSOToken=" \
  --data-urlencode "tfaToken=" \
  --data-urlencode "css=" \
  --data-urlencode "passwordlessAuthnSelected=" \
  --data-urlencode "j_username=$USERNAME" \
  --data-urlencode "j_password=$PASSWORD")

CODE=$(echo $OUTPUT | grep  -Po '.*code=\K.*?(?=\&.*)')

OUTPUT=$(curl --trace-ascii trace2 -s -b /tmp/water.txt -c /tmp/water.txt --location "https://a5xhcq3r8.accounts.ondemand.com/oauth2/token" \
   --data-raw "grant_type=authorization_code&redirect_uri=https%3A%2F%2Fportaaldigitalemeters.water-link.be&code=$CODE&code_verifier=$CODE_VERIFIER&client_id=$CLIENT" \
  -H 'Accept: application/json' \
  -H 'Accept-Language: en-GB,en;q=0.9' \
  -H 'User-Agent: MOT-V9mm/00.62 UP.Browser/6.2.3.4.c.1.123 (GUI) MMP/2.0' \
  -H 'Connection: keep-alive' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -H 'Origin: https://portaaldigitalemeters.water-link.be' \
  -H 'Referer: https://portaaldigitalemeters.water-link.be' \
  -H 'Sec-Fetch-Dest: empty' \
  -H 'Sec-Fetch-Mode: cors' \
  -H 'Sec-Fetch-Site: cross-site' \
  -H 'sec-ch-ua: "Not?A_Brand";v="8", "Chromium";v="108", "Google Chrome";v="108"' \
  -H 'sec-ch-ua-mobile: ?0' \
  -H 'sec-ch-ua-platform: "Windows"'
)

TOKEN=$(echo $OUTPUT |  grep -Po '.*access_token":"\K.*?(?=".*)')

OUTPUT=$(curl --trace-ascii trace3 -s -b /tmp/water.txt -c /tmp/water.txt --location "https://portaaldigitalemeters.water-link.be/api/meters/$METER" \
  -H 'Accept: */*' \
  -H 'Accept-Language: en-GB,en;q=0.9' \
  -H 'Connection: keep-alive' \
  -H "Referer: https://portaaldigitalemeters.water-link.be/water-meter/$METER" \
  -H 'Sec-Fetch-Dest: empty' \
  -H 'Sec-Fetch-Mode: cors' \
  -H 'Sec-Fetch-Site: same-origin' \
  -H 'User-Agent: MOT-V9mm/00.62 UP.Browser/6.2.3.4.c.1.123 (GUI) MMP/2.0' \
  -H "authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' \
  -H 'sec-ch-ua: "Not?A_Brand";v="8", "Chromium";v="108", "Google Chrome";v="108"' \
  -H 'sec-ch-ua-mobile: ?0' \
  -H 'sec-ch-ua-platform: "Windows"' )

echo $OUTPUT
