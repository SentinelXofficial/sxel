package modules

type wafMatch struct {
	Kind    string
	Name    string
	Pattern string
}

type wafSignature struct {
	Vendor       string
	Manufacturer string
	Groups       [][]wafMatch
}

var wafSignatures = []wafSignature{
	{Vendor: `aeSecure`, Manufacturer: `aeSecure`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `aeSecure-code`, Pattern: `.+?`},
		},
	}},
	{Vendor: `aeSecure`, Manufacturer: `aeSecure`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `aesecure_denied\.png`},
		},
	}},
	{Vendor: `AireeCDN`, Manufacturer: `Airee`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `Server`, Pattern: `Airee`},
		},
	}},
	{Vendor: `AireeCDN`, Manufacturer: `Airee`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `X-Cache`, Pattern: `(\w+\.)?airee\.cloud`},
		},
	}},
	{Vendor: `AireeCDN`, Manufacturer: `Airee`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `airee\.cloud`},
		},
	}},
	{Vendor: `Airlock`, Manufacturer: `Phion/Ergon`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `cookie`, Name: ``, Pattern: `^al[_-]?(sess|lb)=`},
		},
	}},
	{Vendor: `Airlock`, Manufacturer: `Phion/Ergon`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `server detected a syntax error in your request`},
		},
	}},
	{Vendor: `Alert Logic`, Manufacturer: `Alert Logic`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `<(title|h\d{1})>requested url cannot be found`},
			wafMatch{Kind: `content`, Name: ``, Pattern: `we are sorry.{0,10}?but the page you are looking for cannot be found`},
			wafMatch{Kind: `content`, Name: ``, Pattern: `back to previous page`},
			wafMatch{Kind: `content`, Name: ``, Pattern: `proceed to homepage`},
			wafMatch{Kind: `content`, Name: ``, Pattern: `reference id`},
		},
	}},
	{Vendor: `AliYunDun`, Manufacturer: `Alibaba Cloud Computing`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `error(s)?\.aliyun(dun)?\.(com|net)?`},
			wafMatch{Kind: `content`, Name: ``, Pattern: `alicdn\.com\/sd\-base\/static\/\d{1,2}\.\d{1,2}\.\d{1,2}\/image\/405\.png`},
			wafMatch{Kind: `status`, Name: `405`, Pattern: ``},
		},
	}},
	{Vendor: `Anquanbao`, Manufacturer: `Anquanbao`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `X-Powered-By-Anquanbao`, Pattern: `.+?`},
		},
	}},
	{Vendor: `Anquanbao`, Manufacturer: `Anquanbao`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `aqb_cc/error/`},
		},
	}},
	{Vendor: `Anubis`, Manufacturer: `Techaro`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `cookie`, Name: ``, Pattern: `-anubis-auth=`},
		},
	}},
	{Vendor: `Anubis`, Manufacturer: `Techaro`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `/\.within\.website/x/cmd/anubis/`},
		},
	}},
	{Vendor: `Anubis`, Manufacturer: `Techaro`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `Protected by.*Anubis.*From.*Techaro`},
		},
	}},
	{Vendor: `Anubis`, Manufacturer: `Techaro`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `github\.com/TecharoHQ/anubis`},
		},
	}},
	{Vendor: `AnYu`, Manufacturer: `AnYu Technologies`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `anyu.{0,10}?the green channel`},
		},
	}},
	{Vendor: `AnYu`, Manufacturer: `AnYu Technologies`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `your access has been intercepted by anyu`},
		},
	}},
	{Vendor: `Azure Application Gateway`, Manufacturer: `Microsoft`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `<center>Microsoft-Azure-Application-Gateway/v2</center>`},
			wafMatch{Kind: `content`, Name: ``, Pattern: `<h1>403 Forbidden</h1>`},
		},
	}},
	{Vendor: `Approach`, Manufacturer: `Approach`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `approach.{0,10}?web application (firewall|filtering)`},
		},
	}},
	{Vendor: `Approach`, Manufacturer: `Approach`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `approach.{0,10}?infrastructure team`},
		},
	}},
	{Vendor: `Armor Defense`, Manufacturer: `Armor`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `blocked by website protection from armor`},
		},
	}},
	{Vendor: `Armor Defense`, Manufacturer: `Armor`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `please create an armor support ticket`},
		},
	}},
	{Vendor: `ArvanCloud`, Manufacturer: `ArvanCloud`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `Server`, Pattern: `ArvanCloud`},
		},
	}},
	{Vendor: `ASPA Firewall`, Manufacturer: `ASPA Engineering Co.`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `Server`, Pattern: `ASPA[\-_]?WAF`},
		},
	}},
	{Vendor: `ASPA Firewall`, Manufacturer: `ASPA Engineering Co.`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `ASPA-Cache-Status`, Pattern: `.+?`},
		},
	}},
	{Vendor: `ASP.NET Generic`, Manufacturer: `Microsoft`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `iis (\d+.)+?detailed error`},
		},
	}},
	{Vendor: `ASP.NET Generic`, Manufacturer: `Microsoft`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `potentially dangerous request querystring`},
		},
	}},
	{Vendor: `ASP.NET Generic`, Manufacturer: `Microsoft`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `application error from being viewed remotely (for security reasons)?`},
		},
	}},
	{Vendor: `ASP.NET Generic`, Manufacturer: `Microsoft`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `An application error occurred on the server`},
		},
	}},
	{Vendor: `Astra`, Manufacturer: `Czar Securities`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `cookie`, Name: ``, Pattern: `^cz_astra_csrf_cookie`},
		},
	}},
	{Vendor: `Astra`, Manufacturer: `Czar Securities`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `astrawebsecurity\.freshdesk\.com`},
		},
	}},
	{Vendor: `Astra`, Manufacturer: `Czar Securities`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `www\.getastra\.com/assets/images`},
		},
	}},
	{Vendor: `AWS Elastic Load Balancer`, Manufacturer: `Amazon`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `X-AMZ-ID`, Pattern: `.+?`},
		},
	}},
	{Vendor: `AWS Elastic Load Balancer`, Manufacturer: `Amazon`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `X-AMZ-Request-ID`, Pattern: `.+?`},
		},
	}},
	{Vendor: `AWS Elastic Load Balancer`, Manufacturer: `Amazon`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `cookie`, Name: ``, Pattern: `^aws.?alb=`},
		},
	}},
	{Vendor: `AWS Elastic Load Balancer`, Manufacturer: `Amazon`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `Server`, Pattern: `aws.?elb`},
		},
	}},
	{Vendor: `AWS Elastic Load Balancer`, Manufacturer: `Amazon`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `X-Blocked-By-WAF`, Pattern: `Blocked_by_custom_response_for_AWSManagedRules.*`},
		},
	}},
	{Vendor: `Azion Edge Firewall`, Manufacturer: `Azion`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `x-azion-edge-pop`, Pattern: `.+?`},
		},
	}},
	{Vendor: `Azion Edge Firewall`, Manufacturer: `Azion`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `x-azion-request-id`, Pattern: `.+?`},
		},
	}},
	{Vendor: `Baffin Bay`, Manufacturer: `Mastercard`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `server`, Pattern: `baffin-bay-inlet`},
		},
	}},
	{Vendor: `Yunjiasu`, Manufacturer: `Baidu Cloud Computing`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `Server`, Pattern: `yunjiasu.*`},
		},
	}},
	{Vendor: `Barikode`, Manufacturer: `Ethic Ninja`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `<strong>barikode<.strong>`},
		},
	}},
	{Vendor: `Barracuda`, Manufacturer: `Barracuda Networks`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `cookie`, Name: ``, Pattern: `^barra_counter_session=`},
		},
	}},
	{Vendor: `Barracuda`, Manufacturer: `Barracuda Networks`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `cookie`, Name: ``, Pattern: `^BNI__BARRACUDA_LB_COOKIE=`},
		},
	}},
	{Vendor: `Barracuda`, Manufacturer: `Barracuda Networks`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `cookie`, Name: ``, Pattern: `^BNI_persistence=`},
		},
	}},
	{Vendor: `Barracuda`, Manufacturer: `Barracuda Networks`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `cookie`, Name: ``, Pattern: `^BN[IE]S_.*?=`},
		},
	}},
	{Vendor: `Barracuda`, Manufacturer: `Barracuda Networks`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `Barracuda.Networks`},
		},
	}},
	{Vendor: `Bekchy`, Manufacturer: `Faydata Technologies Inc.`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `Bekchy.{0,10}?Access Denied`},
		},
	}},
	{Vendor: `Bekchy`, Manufacturer: `Faydata Technologies Inc.`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `bekchy\.com/report`},
		},
	}},
	{Vendor: `Beluga CDN`, Manufacturer: `Beluga`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `Server`, Pattern: `Beluga`},
		},
	}},
	{Vendor: `Beluga CDN`, Manufacturer: `Beluga`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `cookie`, Name: ``, Pattern: `^beluga_request_trail=`},
		},
	}},
	{Vendor: `BinarySec`, Manufacturer: `BinarySec`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `Server`, Pattern: `BinarySec`},
		},
	}},
	{Vendor: `BinarySec`, Manufacturer: `BinarySec`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `x-binarysec-via`, Pattern: `.+`},
		},
	}},
	{Vendor: `BinarySec`, Manufacturer: `BinarySec`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `x-binarysec-nocache`, Pattern: `.+`},
		},
	}},
	{Vendor: `BitNinja`, Manufacturer: `BitNinja`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `Security check by BitNinja`},
		},
	}},
	{Vendor: `BitNinja`, Manufacturer: `BitNinja`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `Visitor anti-robot validation`},
		},
	}},
	{Vendor: `BlockDoS`, Manufacturer: `BlockDoS`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `Server`, Pattern: `blockdos\.net`},
		},
	}},
	{Vendor: `Bluedon`, Manufacturer: `Bluedon IST`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `Server`, Pattern: `BDWAF`},
		},
	}},
	{Vendor: `Bluedon`, Manufacturer: `Bluedon IST`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `bluedon web application firewall`},
		},
	}},
	{Vendor: `BulletProof Security Pro`, Manufacturer: `AITpro Security`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `\+?bpsMessage`},
			wafMatch{Kind: `content`, Name: ``, Pattern: `403 Forbidden Error Page`},
			wafMatch{Kind: `content`, Name: ``, Pattern: `If you arrived here due to a search`},
		},
	}},
	{Vendor: `CacheFly CDN`, Manufacturer: `CacheFly`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `BestCDN`, Pattern: `Cachefly`},
		},
	}},
	{Vendor: `CacheFly CDN`, Manufacturer: `CacheFly`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `cookie`, Name: ``, Pattern: `^cfly_req.*=`},
		},
	}},
	{Vendor: `CacheWall`, Manufacturer: `Varnish`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `Server`, Pattern: `Varnish`},
		},
	}},
	{Vendor: `CacheWall`, Manufacturer: `Varnish`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `X-Varnish`, Pattern: `.+`},
		},
	}},
	{Vendor: `CacheWall`, Manufacturer: `Varnish`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `X-Cachewall-Action`, Pattern: `.+?`},
		},
	}},
	{Vendor: `CacheWall`, Manufacturer: `Varnish`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `X-Cachewall-Reason`, Pattern: `.+?`},
		},
	}},
	{Vendor: `CacheWall`, Manufacturer: `Varnish`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `security by cachewall`},
		},
	}},
	{Vendor: `CacheWall`, Manufacturer: `Varnish`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `403 naughty.{0,10}?not nice!`},
		},
	}},
	{Vendor: `CacheWall`, Manufacturer: `Varnish`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `varnish cache server`},
		},
	}},
	{Vendor: `CdnNS Application Gateway`, Manufacturer: `CdnNs/WdidcNet`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `cdnnswaf application gateway`},
		},
	}},
	{Vendor: `WP Cerber Security`, Manufacturer: `Cerber Tech`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `your request looks suspicious or similar to automated`},
			wafMatch{Kind: `content`, Name: ``, Pattern: `our server stopped processing your request`},
			wafMatch{Kind: `content`, Name: ``, Pattern: `We.re sorry.{0,10}?you are not allowed to proceed`},
			wafMatch{Kind: `content`, Name: ``, Pattern: `requests from spam posting software`},
			wafMatch{Kind: `content`, Name: ``, Pattern: `<title>403 Access Forbidden`},
		},
	}},
	{Vendor: `ChinaCache Load Balancer`, Manufacturer: `ChinaCache`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `Powered-By-ChinaCache`, Pattern: `.+`},
		},
	}},
	{Vendor: `Chuang Yu Shield`, Manufacturer: `Yunaq`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `www\.365cyd\.com`},
		},
	}},
	{Vendor: `Chuang Yu Shield`, Manufacturer: `Yunaq`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `help\.365cyd\.com/cyd\-error\-help.html\?code=403`},
		},
	}},
	{Vendor: `ACE XML Gateway`, Manufacturer: `Cisco`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `Server`, Pattern: `ACE XML Gateway`},
		},
	}},
	{Vendor: `Cloudbric`, Manufacturer: `Penta Security`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `<title>Cloudbric.{0,5}?ERROR!`},
		},
	}},
	{Vendor: `Cloudbric`, Manufacturer: `Penta Security`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `Your request was blocked by Cloudbric`},
		},
	}},
	{Vendor: `Cloudbric`, Manufacturer: `Penta Security`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `please contact Cloudbric Support`},
		},
	}},
	{Vendor: `Cloudbric`, Manufacturer: `Penta Security`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `cloudbric\.zendesk\.com`},
		},
	}},
	{Vendor: `Cloudbric`, Manufacturer: `Penta Security`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `Cloudbric Help Center`},
		},
	}},
	{Vendor: `Cloudbric`, Manufacturer: `Penta Security`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `malformed request syntax.{0,4}?invalid request message framing.{0,4}?or deceptive request routing`},
		},
	}},
	{Vendor: `Cloudflare`, Manufacturer: `Cloudflare Inc.`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `server`, Pattern: `cloudflare`},
		},
	}},
	{Vendor: `Cloudflare`, Manufacturer: `Cloudflare Inc.`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `server`, Pattern: `cloudflare[-_]nginx`},
		},
	}},
	{Vendor: `Cloudflare`, Manufacturer: `Cloudflare Inc.`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `cf-ray`, Pattern: `.+?`},
		},
	}},
	{Vendor: `Cloudflare`, Manufacturer: `Cloudflare Inc.`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `cookie`, Name: ``, Pattern: `__cfduid`},
		},
	}},
	{Vendor: `Cloudfloor`, Manufacturer: `Cloudfloor DNS`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `Server`, Pattern: `CloudfloorDNS(.WAF)?`},
		},
	}},
	{Vendor: `Cloudfloor`, Manufacturer: `Cloudfloor DNS`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `<(title|h\d{1})>CloudfloorDNS.{0,6}?Web Application Firewall Error`},
		},
	}},
	{Vendor: `Cloudfloor`, Manufacturer: `Cloudfloor DNS`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `www\.cloudfloordns\.com/contact`},
		},
	}},
	{Vendor: `Cloudfront`, Manufacturer: `Amazon`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `Server`, Pattern: `Cloudfront`},
		},
	}},
	{Vendor: `Cloudfront`, Manufacturer: `Amazon`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `Via`, Pattern: `([0-9\.]+?)? \w+?\.cloudfront\.net \(Cloudfront\)`},
		},
	}},
	{Vendor: `Cloudfront`, Manufacturer: `Amazon`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `X-Amz-Cf-Id`, Pattern: `.+?`},
		},
	}},
	{Vendor: `Cloudfront`, Manufacturer: `Amazon`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `X-Cache`, Pattern: `Error from Cloudfront`},
		},
	}},
	{Vendor: `Cloudfront`, Manufacturer: `Amazon`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `Generated by cloudfront \(CloudFront\)`},
		},
	}},
	{Vendor: `Cloud Protector`, Manufacturer: `Rohde & Schwarz CyberSecurity`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `Cloud Protector.*?by Rohde.{3,8}?Schwarz Cybersecurity`},
		},
	}},
	{Vendor: `Comodo cWatch`, Manufacturer: `Comodo CyberSecurity`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `Server`, Pattern: `Protected by COMODO WAF(.+)?`},
		},
	}},
	{Vendor: `CrawlProtect`, Manufacturer: `Jean-Denis Brun`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `cookie`, Name: ``, Pattern: `^crawlprotecttag=`},
		},
	}},
	{Vendor: `CrawlProtect`, Manufacturer: `Jean-Denis Brun`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `<title>crawlprotect`},
		},
	}},
	{Vendor: `CrawlProtect`, Manufacturer: `Jean-Denis Brun`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `this site is protected by crawlprotect`},
		},
	}},
	{Vendor: `DDoS-GUARD`, Manufacturer: `DDOS-GUARD CORP.`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `cookie`, Name: ``, Pattern: `^__ddg1.*?=`},
		},
	}},
	{Vendor: `DDoS-GUARD`, Manufacturer: `DDOS-GUARD CORP.`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `cookie`, Name: ``, Pattern: `^__ddg2.*?=`},
		},
	}},
	{Vendor: `DDoS-GUARD`, Manufacturer: `DDOS-GUARD CORP.`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `cookie`, Name: ``, Pattern: `^__ddgid.*?=`},
		},
	}},
	{Vendor: `DDoS-GUARD`, Manufacturer: `DDOS-GUARD CORP.`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `cookie`, Name: ``, Pattern: `^__ddgmark.*?=`},
		},
	}},
	{Vendor: `DDoS-GUARD`, Manufacturer: `DDOS-GUARD CORP.`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `Server`, Pattern: `ddos-guard`},
		},
	}},
	{Vendor: `DenyALL`, Manufacturer: `Rohde & Schwarz CyberSecurity`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `status`, Name: `200`, Pattern: ``},
			wafMatch{Kind: `reason`, Name: ``, Pattern: `Condition Intercepted`},
		},
	}},
	{Vendor: `Distil`, Manufacturer: `Distil Networks`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `cdn\.distilnetworks\.com/images/anomaly\.detected\.png`},
		},
	}},
	{Vendor: `Distil`, Manufacturer: `Distil Networks`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `distilCaptchaForm`},
		},
	}},
	{Vendor: `Distil`, Manufacturer: `Distil Networks`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `distilCallbackGuard`},
		},
	}},
	{Vendor: `DOSarrest`, Manufacturer: `DOSarrest Internet Security`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `X-DIS-Request-ID`, Pattern: `.+`},
		},
	}},
	{Vendor: `DOSarrest`, Manufacturer: `DOSarrest Internet Security`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `Server`, Pattern: `DOSarrest(.*)?`},
		},
	}},
	{Vendor: `DotDefender`, Manufacturer: `Applicure Technologies`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `X-dotDefender-denied`, Pattern: `.+?`},
		},
	}},
	{Vendor: `DotDefender`, Manufacturer: `Applicure Technologies`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `dotdefender blocked your request`},
		},
	}},
	{Vendor: `DotDefender`, Manufacturer: `Applicure Technologies`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `Applicure is the leading provider of web application security`},
		},
	}},
	{Vendor: `DynamicWeb Injection Check`, Manufacturer: `DynamicWeb`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `X-403-Status-By`, Pattern: `dw.inj.check`},
		},
	}},
	{Vendor: `DynamicWeb Injection Check`, Manufacturer: `DynamicWeb`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `by dynamic check(.{0,10}?module)?`},
		},
	}},
	{Vendor: `Edgecast`, Manufacturer: `Verizon Digital Media`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `Server`, Pattern: `^ECD(.+)?`},
		},
	}},
	{Vendor: `Edgecast`, Manufacturer: `Verizon Digital Media`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `Server`, Pattern: `^ECS(.*)?`},
		},
	}},
	{Vendor: `Eisoo Cloud Firewall`, Manufacturer: `Eisoo`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `Server`, Pattern: `EisooWAF(\-AZURE)?/?`},
		},
	}},
	{Vendor: `Eisoo Cloud Firewall`, Manufacturer: `Eisoo`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `www\.eisoo\.com`},
		},
	}},
	{Vendor: `Eisoo Cloud Firewall`, Manufacturer: `Eisoo`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `&copy; \d{4} Eisoo Inc`},
		},
	}},
	{Vendor: `Envoy`, Manufacturer: `EnvoyProxy`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `server`, Pattern: `envoy`},
		},
	}},
	{Vendor: `Envoy`, Manufacturer: `EnvoyProxy`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `x-envoy-upstream-service-time`, Pattern: `.+`},
		},
	}},
	{Vendor: `Envoy`, Manufacturer: `EnvoyProxy`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `x-envoy-downstream-service-cluster`, Pattern: `.+`},
		},
	}},
	{Vendor: `Envoy`, Manufacturer: `EnvoyProxy`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `x-envoy-downstream-service-node`, Pattern: `.+`},
		},
	}},
	{Vendor: `Envoy`, Manufacturer: `EnvoyProxy`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `x-envoy-external-address`, Pattern: `.+`},
		},
	}},
	{Vendor: `Envoy`, Manufacturer: `EnvoyProxy`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `x-envoy-force-trace`, Pattern: `.+`},
		},
	}},
	{Vendor: `Envoy`, Manufacturer: `EnvoyProxy`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `x-envoy-internal`, Pattern: `.+`},
		},
	}},
	{Vendor: `Envoy`, Manufacturer: `EnvoyProxy`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `x-envoy-original-dst-host`, Pattern: `.+`},
		},
	}},
	{Vendor: `Envoy`, Manufacturer: `EnvoyProxy`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `x-envoy-original-path`, Pattern: `.+`},
		},
	}},
	{Vendor: `Envoy`, Manufacturer: `EnvoyProxy`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `x-envoy-local-overloaded`, Pattern: `.+`},
		},
	}},
	{Vendor: `Expression Engine`, Manufacturer: `EllisLab`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `cookie`, Name: ``, Pattern: `^exp_track.+?=`},
		},
	}},
	{Vendor: `Expression Engine`, Manufacturer: `EllisLab`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `invalid get data`},
		},
	}},
	{Vendor: `BIG-IP AP Manager`, Manufacturer: `F5 Networks`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `cookie`, Name: ``, Pattern: `^LastMRH_Session`},
			wafMatch{Kind: `cookie`, Name: ``, Pattern: `^MRHSession`},
		},
	}},
	{Vendor: `BIG-IP AP Manager`, Manufacturer: `F5 Networks`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `cookie`, Name: ``, Pattern: `^MRHSession`},
			wafMatch{Kind: `header`, Name: `Server`, Pattern: `Big([-_])?IP`},
		},
	}},
	{Vendor: `BIG-IP AP Manager`, Manufacturer: `F5 Networks`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `cookie`, Name: ``, Pattern: `^F5_fullWT`},
		},
	}},
	{Vendor: `BIG-IP AP Manager`, Manufacturer: `F5 Networks`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `cookie`, Name: ``, Pattern: `^F5_HT_shrinked`},
		},
	}},
	{Vendor: `BIG-IP AppSec Manager`, Manufacturer: `F5 Networks`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `the requested url was rejected`},
			wafMatch{Kind: `content`, Name: ``, Pattern: `please consult with your administrator`},
		},
	}},
	{Vendor: `BIG-IP AppSec Manager`, Manufacturer: `F5 Networks`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `cookie`, Name: ``, Pattern: `TS[a-fA-F0-9]{8}=.+`},
		},
	}},
	{Vendor: `BIG-IP AppSec Manager`, Manufacturer: `F5 Networks`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `cookie`, Name: ``, Pattern: `TS[a-fA-F0-9]{6}=.+`},
		},
	}},
	{Vendor: `BIG-IP Local Traffic Manager`, Manufacturer: `F5 Networks`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `cookie`, Name: ``, Pattern: `^bigipserver`},
		},
	}},
	{Vendor: `BIG-IP Local Traffic Manager`, Manufacturer: `F5 Networks`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `X-Cnection`, Pattern: `close`},
		},
	}},
	{Vendor: `FirePass`, Manufacturer: `F5 Networks`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `cookie`, Name: ``, Pattern: `^VHOST`},
			wafMatch{Kind: `header`, Name: `Location`, Pattern: `\/my\.logon\.php3`},
		},
	}},
	{Vendor: `FirePass`, Manufacturer: `F5 Networks`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `cookie`, Name: ``, Pattern: `^F5_fire.+?`},
			wafMatch{Kind: `cookie`, Name: ``, Pattern: `^F5_passid_shrinked`},
		},
	}},
	{Vendor: `Trafficshield`, Manufacturer: `F5 Networks`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `cookie`, Name: ``, Pattern: `^ASINFO=`},
		},
	}},
	{Vendor: `Trafficshield`, Manufacturer: `F5 Networks`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `Server`, Pattern: `F5-TrafficShield`},
		},
	}},
	{Vendor: `Fastly`, Manufacturer: `Fastly CDN`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `X-Fastly-Request-ID`, Pattern: `\w+`},
		},
	}},
	{Vendor: `Fastly`, Manufacturer: `Fastly CDN`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `X-Served-By`, Pattern: `^cache-[a-z]{3}\d+-[A-Z]{3}`},
		},
	}},
	{Vendor: `FortiGate`, Manufacturer: `Fortinet`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `//globalurl.fortinet.net`},
			wafMatch{Kind: `content`, Name: ``, Pattern: `FortiGate Application Control`},
		},
	}},
	{Vendor: `FortiGate`, Manufacturer: `Fortinet`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `Web Application Firewall`},
			wafMatch{Kind: `content`, Name: ``, Pattern: `Event ID`},
			wafMatch{Kind: `content`, Name: ``, Pattern: `//globalurl.fortinet.net`},
		},
	}},
	{Vendor: `FortiGuard`, Manufacturer: `Fortinet`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `FortiGuard Intrusion Prevention`},
		},
	}},
	{Vendor: `FortiGuard`, Manufacturer: `Fortinet`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `//globalurl.fortinet.net`},
		},
	}},
	{Vendor: `FortiWeb`, Manufacturer: `Fortinet`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `cookie`, Name: ``, Pattern: `^FORTIWAFSID=`},
		},
	}},
	{Vendor: `FortiWeb`, Manufacturer: `Fortinet`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `.fgd_icon`},
		},
	}},
	{Vendor: `FortiWeb`, Manufacturer: `Fortinet`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `fgd_icon`},
			wafMatch{Kind: `content`, Name: ``, Pattern: `web.page.blocked`},
			wafMatch{Kind: `content`, Name: ``, Pattern: `url`},
			wafMatch{Kind: `content`, Name: ``, Pattern: `attack.id`},
			wafMatch{Kind: `content`, Name: ``, Pattern: `message.id`},
			wafMatch{Kind: `content`, Name: ``, Pattern: `client.ip`},
		},
	}},
	{Vendor: `Azure Front Door`, Manufacturer: `Microsoft`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `X-Azure-Ref`, Pattern: `.+?`},
		},
	}},
	{Vendor: `Google Cloud App Armor`, Manufacturer: `Google Cloud`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `Via`, Pattern: `1.1 google`},
		},
	}},
	{Vendor: `GoDaddy Website Protection`, Manufacturer: `GoDaddy`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `GoDaddy (security|website firewall)`},
		},
	}},
	{Vendor: `Greywizard`, Manufacturer: `Grey Wizard`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `Server`, Pattern: `greywizard`},
		},
	}},
	{Vendor: `Greywizard`, Manufacturer: `Grey Wizard`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `<(title|h\d{1})>Grey Wizard`},
		},
	}},
	{Vendor: `Greywizard`, Manufacturer: `Grey Wizard`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `contact the website owner or Grey Wizard`},
		},
	}},
	{Vendor: `Greywizard`, Manufacturer: `Grey Wizard`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `We.ve detected attempted attack or non standard traffic from your ip address`},
		},
	}},
	{Vendor: `Huawei Cloud Firewall`, Manufacturer: `Huawei`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `cookie`, Name: ``, Pattern: `^HWWAFSESID=`},
		},
	}},
	{Vendor: `Huawei Cloud Firewall`, Manufacturer: `Huawei`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `Server`, Pattern: `HuaweiCloudWAF`},
		},
	}},
	{Vendor: `Huawei Cloud Firewall`, Manufacturer: `Huawei`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `hwclouds\.com`},
		},
	}},
	{Vendor: `Huawei Cloud Firewall`, Manufacturer: `Huawei`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `hws_security@`},
		},
	}},
	{Vendor: `HyperGuard`, Manufacturer: `Art of Defense`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `cookie`, Name: ``, Pattern: `^WODSESSION=`},
		},
	}},
	{Vendor: `DataPower`, Manufacturer: `IBM`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `X-Backside-Transport`, Pattern: `(OK|FAIL)`},
		},
	}},
	{Vendor: `Imunify360`, Manufacturer: `CloudLinux`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `Server`, Pattern: `imunify360.{0,10}?`},
		},
	}},
	{Vendor: `Imunify360`, Manufacturer: `CloudLinux`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `protected.by.{0,10}?imunify360`},
		},
	}},
	{Vendor: `Imunify360`, Manufacturer: `CloudLinux`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `powered.by.{0,10}?imunify360`},
		},
	}},
	{Vendor: `Imunify360`, Manufacturer: `CloudLinux`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `imunify360.preloader`},
		},
	}},
	{Vendor: `Incapsula`, Manufacturer: `Imperva Inc.`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `cookie`, Name: ``, Pattern: `^incap_ses.*?=`},
		},
	}},
	{Vendor: `Incapsula`, Manufacturer: `Imperva Inc.`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `cookie`, Name: ``, Pattern: `^visid_incap.*?=`},
		},
	}},
	{Vendor: `Incapsula`, Manufacturer: `Imperva Inc.`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `incapsula incident id`},
		},
	}},
	{Vendor: `Incapsula`, Manufacturer: `Imperva Inc.`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `powered by incapsula`},
		},
	}},
	{Vendor: `Incapsula`, Manufacturer: `Imperva Inc.`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `/_Incapsula_Resource`},
		},
	}},
	{Vendor: `IndusGuard`, Manufacturer: `Indusface`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `Server`, Pattern: `IF_WAF`},
		},
	}},
	{Vendor: `IndusGuard`, Manufacturer: `Indusface`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `This website is secured against online attacks. Your request was blocked`},
		},
	}},
	{Vendor: `Instart DX`, Manufacturer: `Instart Logic`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `X-Instart-Request-ID`, Pattern: `.+`},
		},
	}},
	{Vendor: `Instart DX`, Manufacturer: `Instart Logic`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `X-Instart-Cache`, Pattern: `.+`},
		},
	}},
	{Vendor: `Instart DX`, Manufacturer: `Instart Logic`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `X-Instart-WL`, Pattern: `.+`},
		},
	}},
	{Vendor: `Instart DX`, Manufacturer: `Instart Logic`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `the requested url was rejected`},
			wafMatch{Kind: `content`, Name: ``, Pattern: `please consult with your administrator`},
			wafMatch{Kind: `content`, Name: ``, Pattern: `your support id is`},
		},
	}},
	{Vendor: `ISA Server`, Manufacturer: `Microsoft`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `The.{0,10}?(isa.)?server.{0,10}?denied the specified uniform resource locator \(url\)`},
		},
	}},
	{Vendor: `Janusec Application Gateway`, Manufacturer: `Janusec`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `janusec application gateway`},
		},
	}},
	{Vendor: `Jiasule`, Manufacturer: `Jiasule`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `Server`, Pattern: `jiasule\-waf`},
		},
	}},
	{Vendor: `Jiasule`, Manufacturer: `Jiasule`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `cookie`, Name: ``, Pattern: `^jsl_tracking(.+)?=`},
		},
	}},
	{Vendor: `Jiasule`, Manufacturer: `Jiasule`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `cookie`, Name: ``, Pattern: `__jsluid=`},
		},
	}},
	{Vendor: `Jiasule`, Manufacturer: `Jiasule`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `notice\-jiasule`},
		},
	}},
	{Vendor: `Jiasule`, Manufacturer: `Jiasule`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `static\.jiasule\.com`},
		},
	}},
	{Vendor: `Kemp LoadMaster`, Manufacturer: `Progress Software`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `X-ServedBy`, Pattern: `KEMP-LM`},
			wafMatch{Kind: `content`, Name: ``, Pattern: `<title>403 Forbidden</title>`},
			wafMatch{Kind: `status`, Name: `403`, Pattern: ``},
		},
	}},
	{Vendor: `KeyCDN`, Manufacturer: `KeyCDN`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `Server`, Pattern: `KeyCDN`},
		},
	}},
	{Vendor: `KS-WAF`, Manufacturer: `KnownSec`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `/ks[-_]waf[-_]error\.png`},
		},
	}},
	{Vendor: `Kona SiteDefender`, Manufacturer: `Akamai`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `Server`, Pattern: `AkamaiGHost`},
		},
	}},
	{Vendor: `LimeLight CDN`, Manufacturer: `LimeLight`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `cookie`, Name: ``, Pattern: `^limelight`},
		},
	}},
	{Vendor: `LimeLight CDN`, Manufacturer: `LimeLight`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `cookie`, Name: ``, Pattern: `^l[mg]_sessid=`},
		},
	}},
	{Vendor: `Link11 WAAP`, Manufacturer: `Link11`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `server`, Pattern: `rhino-core-shield`},
		},
	}},
	{Vendor: `LiteSpeed`, Manufacturer: `LiteSpeed Technologies`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `Server`, Pattern: `LiteSpeed`},
			wafMatch{Kind: `status`, Name: `403`, Pattern: ``},
		},
	}},
	{Vendor: `LiteSpeed`, Manufacturer: `LiteSpeed Technologies`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `Proudly powered by litespeed web server`},
		},
	}},
	{Vendor: `LiteSpeed`, Manufacturer: `LiteSpeed Technologies`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `www\.litespeedtech\.com/error\-page`},
		},
	}},
	{Vendor: `Malcare`, Manufacturer: `Inactiv`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `firewall.{0,15}?powered.by.{0,15}?malcare.{0,15}?pro`},
		},
	}},
	{Vendor: `Malcare`, Manufacturer: `Inactiv`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `blocked because of malicious activities`},
		},
	}},
	{Vendor: `MaxCDN`, Manufacturer: `MaxCDN`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `X-CDN`, Pattern: `maxcdn`},
		},
	}},
	{Vendor: `Mission Control Shield`, Manufacturer: `Mission Control`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `Server`, Pattern: `Mission Control Application Shield`},
		},
	}},
	{Vendor: `ModSecurity`, Manufacturer: `SpiderLabs`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `Server`, Pattern: `(mod_security|Mod_Security|NOYB)`},
		},
	}},
	{Vendor: `ModSecurity`, Manufacturer: `SpiderLabs`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `This error was generated by Mod.?Security`},
		},
	}},
	{Vendor: `ModSecurity`, Manufacturer: `SpiderLabs`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `rules of the mod.security.module`},
		},
	}},
	{Vendor: `ModSecurity`, Manufacturer: `SpiderLabs`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `mod.security.rules triggered`},
		},
	}},
	{Vendor: `ModSecurity`, Manufacturer: `SpiderLabs`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `Protected by Mod.?Security`},
		},
	}},
	{Vendor: `ModSecurity`, Manufacturer: `SpiderLabs`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `/modsecurity[\-_]errorpage/`},
		},
	}},
	{Vendor: `ModSecurity`, Manufacturer: `SpiderLabs`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `modsecurity iis`},
		},
	}},
	{Vendor: `ModSecurity`, Manufacturer: `SpiderLabs`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `reason`, Name: ``, Pattern: `ModSecurity Action`},
			wafMatch{Kind: `status`, Name: `403`, Pattern: ``},
		},
	}},
	{Vendor: `ModSecurity`, Manufacturer: `SpiderLabs`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `reason`, Name: ``, Pattern: `ModSecurity Action`},
			wafMatch{Kind: `status`, Name: `406`, Pattern: ``},
		},
	}},
	{Vendor: `NAXSI`, Manufacturer: `NBS Systems`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `X-Data-Origin`, Pattern: `^naxsi(.+)?`},
		},
	}},
	{Vendor: `NAXSI`, Manufacturer: `NBS Systems`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `Server`, Pattern: `naxsi(.+)?`},
		},
	}},
	{Vendor: `NAXSI`, Manufacturer: `NBS Systems`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `blocked by naxsi`},
		},
	}},
	{Vendor: `NAXSI`, Manufacturer: `NBS Systems`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `naxsi blocked information`},
		},
	}},
	{Vendor: `Nemesida`, Manufacturer: `PentestIt`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `@?nemesida(\-security)?\.com`},
		},
	}},
	{Vendor: `Nemesida`, Manufacturer: `PentestIt`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `Suspicious activity detected.{0,10}?Access to the site is blocked`},
		},
	}},
	{Vendor: `Nemesida`, Manufacturer: `PentestIt`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `nwaf@`},
		},
	}},
	{Vendor: `Nemesida`, Manufacturer: `PentestIt`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `status`, Name: `222`, Pattern: ``},
		},
	}},
	{Vendor: `NetContinuum`, Manufacturer: `Barracuda Networks`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `cookie`, Name: ``, Pattern: `^NCI__SessionId=`},
		},
	}},
	{Vendor: `NetScaler AppFirewall`, Manufacturer: `Citrix Systems`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `Via`, Pattern: `NS\-CACHE`},
		},
	}},
	{Vendor: `NetScaler AppFirewall`, Manufacturer: `Citrix Systems`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `cookie`, Name: ``, Pattern: `^(ns_af=|citrix_ns_id|NSC_)`},
		},
	}},
	{Vendor: `NetScaler AppFirewall`, Manufacturer: `Citrix Systems`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `(NS Transaction|AppFW Session) id`},
		},
	}},
	{Vendor: `NetScaler AppFirewall`, Manufacturer: `Citrix Systems`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `Violation Category.{0,5}?APPFW_`},
		},
	}},
	{Vendor: `NetScaler AppFirewall`, Manufacturer: `Citrix Systems`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `Citrix\|NetScaler`},
		},
	}},
	{Vendor: `NetScaler AppFirewall`, Manufacturer: `Citrix Systems`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `Cneonction`, Pattern: `^(keep alive|close)`},
		},
	}},
	{Vendor: `NetScaler AppFirewall`, Manufacturer: `Citrix Systems`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `nnCoection`, Pattern: `^(keep alive|close)`},
		},
	}},
	{Vendor: `NevisProxy`, Manufacturer: `AdNovum`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `cookie`, Name: ``, Pattern: `^Navajo`},
		},
	}},
	{Vendor: `NevisProxy`, Manufacturer: `AdNovum`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `cookie`, Name: ``, Pattern: `^NP_ID`},
		},
	}},
	{Vendor: `Newdefend`, Manufacturer: `NewDefend`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `Server`, Pattern: `Newdefend`},
		},
	}},
	{Vendor: `Newdefend`, Manufacturer: `NewDefend`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `www\.newdefend\.com/feedback`},
		},
	}},
	{Vendor: `Newdefend`, Manufacturer: `NewDefend`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `/nd\-block/`},
		},
	}},
	{Vendor: `NexusGuard Firewall`, Manufacturer: `NexusGuard`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `Powered by Nexusguard`},
		},
	}},
	{Vendor: `NexusGuard Firewall`, Manufacturer: `NexusGuard`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `nexusguard\.com/wafpage/.+#\d{3};`},
		},
	}},
	{Vendor: `NinjaFirewall`, Manufacturer: `NinTechNet`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `<title>NinjaFirewall.{0,10}?\d{3}.forbidden`},
			wafMatch{Kind: `content`, Name: ``, Pattern: `For security reasons?.{0,10}?it was blocked and logged`},
		},
	}},
	{Vendor: `NSFocus`, Manufacturer: `NSFocus Global Inc.`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `Server`, Pattern: `NSFocus`},
		},
	}},
	{Vendor: `NullDDoS Protection`, Manufacturer: `NullDDoS`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `Server`, Pattern: `NullDDoS(.System)?`},
		},
	}},
	{Vendor: `OnMessage Shield`, Manufacturer: `BlackBaud`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `X-Engine`, Pattern: `onMessage Shield`},
		},
	}},
	{Vendor: `OnMessage Shield`, Manufacturer: `BlackBaud`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `Blackbaud K\-12 conducts routine maintenance`},
		},
	}},
	{Vendor: `OnMessage Shield`, Manufacturer: `BlackBaud`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `onMessage SHEILD`},
		},
	}},
	{Vendor: `OnMessage Shield`, Manufacturer: `BlackBaud`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `maintenance\.blackbaud\.com`},
		},
	}},
	{Vendor: `OnMessage Shield`, Manufacturer: `BlackBaud`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `status\.blackbaud\.com`},
		},
	}},
	{Vendor: `Open-Resty Lua Nginx`, Manufacturer: `FLOSS`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `Server`, Pattern: `^openresty/[0-9\.]+?`},
			wafMatch{Kind: `status`, Name: `403`, Pattern: ``},
		},
	}},
	{Vendor: `Open-Resty Lua Nginx`, Manufacturer: `FLOSS`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `openresty/[0-9\.]+?`},
			wafMatch{Kind: `status`, Name: `406`, Pattern: ``},
		},
	}},
	{Vendor: `Oracle Cloud`, Manufacturer: `Oracle`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `<title>fw_error_www`},
		},
	}},
	{Vendor: `Oracle Cloud`, Manufacturer: `Oracle`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `www\.oracleimg\.com/us/assets/metrics/ora_ocom\.js`},
		},
	}},
	{Vendor: `Palo Alto Next Gen Firewall`, Manufacturer: `Palo Alto Networks`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `Download of virus.spyware blocked`},
		},
	}},
	{Vendor: `Palo Alto Next Gen Firewall`, Manufacturer: `Palo Alto Networks`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `Palo Alto Next Generation Security Platform`},
		},
	}},
	{Vendor: `360PanYun`, Manufacturer: `360 Technologies`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `Server`, Pattern: `panyun`},
		},
	}},
	{Vendor: `360PanYun`, Manufacturer: `360 Technologies`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `X-Panyun-Request-ID`, Pattern: `.+?`},
		},
	}},
	{Vendor: `360PanYun`, Manufacturer: `360 Technologies`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `X-Panyun-Error-Reason`, Pattern: `.+?`},
		},
	}},
	{Vendor: `360PanYun`, Manufacturer: `360 Technologies`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `X-Panyun-Error-Step`, Pattern: `.+?`},
		},
	}},
	{Vendor: `PentaWAF`, Manufacturer: `Global Network Services`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `Server`, Pattern: `PentaWaf(/[0-9\.]+)?`},
		},
	}},
	{Vendor: `PentaWAF`, Manufacturer: `Global Network Services`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `Penta.?Waf/[0-9\.]+?.server`},
		},
	}},
	{Vendor: `PerimeterX`, Manufacturer: `PerimeterX`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `www\.perimeterx\.(com|net)/whywasiblocked`},
		},
	}},
	{Vendor: `PerimeterX`, Manufacturer: `PerimeterX`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `client\.perimeterx\.(net|com)`},
		},
	}},
	{Vendor: `PerimeterX`, Manufacturer: `PerimeterX`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `denied because we believe you are using automation tools`},
		},
	}},
	{Vendor: `pkSecurity IDS`, Manufacturer: `pkSec`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `pk.?Security.?Module`},
		},
	}},
	{Vendor: `pkSecurity IDS`, Manufacturer: `pkSec`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `Security.Alert`},
		},
	}},
	{Vendor: `pkSecurity IDS`, Manufacturer: `pkSec`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `As this could be a potential hack attack`},
			wafMatch{Kind: `content`, Name: ``, Pattern: `A safety critical (call|request) was (detected|discovered) and blocked`},
			wafMatch{Kind: `content`, Name: ``, Pattern: `maximum number of reloads per minute and prevented access`},
		},
	}},
	{Vendor: `PowerCDN`, Manufacturer: `PowerCDN`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `Via`, Pattern: `(.*)?powercdn.com(.*)?`},
		},
	}},
	{Vendor: `PowerCDN`, Manufacturer: `PowerCDN`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `X-Cache`, Pattern: `(.*)?powercdn.com(.*)?`},
		},
	}},
	{Vendor: `PowerCDN`, Manufacturer: `PowerCDN`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `X-CDN`, Pattern: `PowerCDN`},
		},
	}},
	{Vendor: `Profense`, Manufacturer: `ArmorLogic`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `Server`, Pattern: `Profense`},
		},
	}},
	{Vendor: `Profense`, Manufacturer: `ArmorLogic`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `cookie`, Name: ``, Pattern: `^PLBSID=`},
		},
	}},
	{Vendor: `PT Application Firewall`, Manufacturer: `Positive Technologies`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `<h1.{0,10}?Forbidden`},
			wafMatch{Kind: `content`, Name: ``, Pattern: `<pre>Request.ID:.{0,10}?\d{4}\-(\d{2})+.{0,35}?pre>`},
		},
	}},
	{Vendor: `Puhui`, Manufacturer: `Puhui`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `Server`, Pattern: `Puhui[\-_]?WAF`},
		},
	}},
	{Vendor: `Qcloud`, Manufacturer: `Tencent Cloud`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `腾讯云Web应用防火墙`},
			wafMatch{Kind: `status`, Name: `403`, Pattern: ``},
		},
	}},
	{Vendor: `Qiniu`, Manufacturer: `Qiniu CDN`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `X-Qiniu-CDN`, Pattern: `\d+?`},
		},
	}},
	{Vendor: `Qrator`, Manufacturer: `Qrator`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `Server`, Pattern: `QRATOR`},
		},
	}},
	{Vendor: `AppWall`, Manufacturer: `Radware`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `CloudWebSec\.radware\.com`},
		},
	}},
	{Vendor: `AppWall`, Manufacturer: `Radware`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `X-SL-CompState`, Pattern: `.+`},
		},
	}},
	{Vendor: `AppWall`, Manufacturer: `Radware`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `because we have detected unauthorized activity`},
			wafMatch{Kind: `content`, Name: ``, Pattern: `<title>Unauthorized Request Blocked`},
			wafMatch{Kind: `content`, Name: ``, Pattern: `if you believe that there has been some mistake`},
			wafMatch{Kind: `content`, Name: ``, Pattern: `\?Subject=Security Page.{0,10}?Case Number`},
		},
	}},
	{Vendor: `Reblaze`, Manufacturer: `Reblaze`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `cookie`, Name: ``, Pattern: `^rbzid`},
		},
	}},
	{Vendor: `Reblaze`, Manufacturer: `Reblaze`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `Server`, Pattern: `Reblaze Secure Web Gateway`},
		},
	}},
	{Vendor: `Reblaze`, Manufacturer: `Reblaze`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `current session has been terminated`},
			wafMatch{Kind: `content`, Name: ``, Pattern: `do not hesitate to contact us`},
			wafMatch{Kind: `content`, Name: ``, Pattern: `access denied \(\d{3}\)`},
		},
	}},
	{Vendor: `Reflected Networks`, Manufacturer: `Reflected Networks`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `<title>Forbidden</title>`},
			wafMatch{Kind: `status`, Name: `403`, Pattern: ``},
		},
	}},
	{Vendor: `RSFirewall`, Manufacturer: `RSJoomla!`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `com_rsfirewall_(\d{3}_forbidden|event)?`},
		},
	}},
	{Vendor: `RequestValidationMode`, Manufacturer: `Microsoft`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `Request Validation has detected a potentially dangerous client input`},
		},
	}},
	{Vendor: `RequestValidationMode`, Manufacturer: `Microsoft`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `ASP\.NET has detected data in the request`},
		},
	}},
	{Vendor: `RequestValidationMode`, Manufacturer: `Microsoft`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `HttpRequestValidationException`},
		},
	}},
	{Vendor: `Sabre Firewall`, Manufacturer: `Sabre`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `dxsupport\.sabre\.com`},
		},
	}},
	{Vendor: `Sabre Firewall`, Manufacturer: `Sabre`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `<title>Application Firewall Error`},
			wafMatch{Kind: `content`, Name: ``, Pattern: `add some important details to the email for us to investigate`},
		},
	}},
	{Vendor: `Safe3 Web Firewall`, Manufacturer: `Safe3`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `Server`, Pattern: `Safe3 Web Firewall`},
		},
	}},
	{Vendor: `Safe3 Web Firewall`, Manufacturer: `Safe3`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `X-Powered-By`, Pattern: `Safe3WAF/[\.0-9]+?`},
		},
	}},
	{Vendor: `Safe3 Web Firewall`, Manufacturer: `Safe3`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `Safe3waf/[0-9\.]+?`},
		},
	}},
	{Vendor: `Safedog`, Manufacturer: `SafeDog`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `cookie`, Name: ``, Pattern: `^safedog\-flow\-item=`},
		},
	}},
	{Vendor: `Safedog`, Manufacturer: `SafeDog`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `Server`, Pattern: `Safedog`},
		},
	}},
	{Vendor: `Safedog`, Manufacturer: `SafeDog`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `safedogsite/broswer_logo\.jpg`},
		},
	}},
	{Vendor: `Safedog`, Manufacturer: `SafeDog`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `404\.safedog\.cn/sitedog_stat.html`},
		},
	}},
	{Vendor: `Safedog`, Manufacturer: `SafeDog`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `404\.safedog\.cn/images/safedogsite/head\.png`},
		},
	}},
	{Vendor: `Safeline`, Manufacturer: `Chaitin Tech.`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `safeline|<!\-\-\sevent id:`},
		},
	}},
	{Vendor: `Scutum`, Manufacturer: `Secure Sky Technology Inc.`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `Server`, Pattern: `Scutum`},
		},
	}},
	{Vendor: `SecKing`, Manufacturer: `SecKing`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `Server`, Pattern: `secking(.?waf)?`},
		},
	}},
	{Vendor: `SecuPress WP Security`, Manufacturer: `SecuPress`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `<(title|h\d{1})>SecuPress`},
		},
	}},
	{Vendor: `Secure Entry`, Manufacturer: `United Security Providers`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `Server`, Pattern: `Secure Entry Server`},
		},
	}},
	{Vendor: `eEye SecureIIS`, Manufacturer: `BeyondTrust`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `SecureIIS is an internet security application`},
		},
	}},
	{Vendor: `eEye SecureIIS`, Manufacturer: `BeyondTrust`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `Download SecureIIS Personal Edition`},
		},
	}},
	{Vendor: `eEye SecureIIS`, Manufacturer: `BeyondTrust`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `https?://www\.eeye\.com/Secure\-?IIS`},
		},
	}},
	{Vendor: `SecureSphere`, Manufacturer: `Imperva Inc.`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `<(title|h2)>Error`},
			wafMatch{Kind: `content`, Name: ``, Pattern: `The incident ID is`},
			wafMatch{Kind: `content`, Name: ``, Pattern: `Contact support for additional information`},
		},
	}},
	{Vendor: `SEnginx`, Manufacturer: `Neusoft`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `SENGINX\-ROBOT\-MITIGATION`},
		},
	}},
	{Vendor: `ServerDefender VP`, Manufacturer: `Port80 Software`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `X-Pint`, Pattern: `p(ort\-)?80`},
		},
	}},
	{Vendor: `Shadow Daemon`, Manufacturer: `Zecure`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `<h\d{1}>\d{3}.forbidden<.h\d{1}>`},
			wafMatch{Kind: `content`, Name: ``, Pattern: `request forbidden by administrative rules`},
		},
	}},
	{Vendor: `Shieldon Firewall`, Manufacturer: `Shieldon.io`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `Please solve CAPTCHA`},
			wafMatch{Kind: `content`, Name: ``, Pattern: `shieldon_captcha`},
			wafMatch{Kind: `content`, Name: ``, Pattern: `Unusual behavior detected`},
			wafMatch{Kind: `content`, Name: ``, Pattern: `status-user-info`},
		},
	}},
	{Vendor: `Shieldon Firewall`, Manufacturer: `Shieldon.io`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `Access denied`},
			wafMatch{Kind: `content`, Name: ``, Pattern: `The IP address you are using has been blocked.`},
			wafMatch{Kind: `content`, Name: ``, Pattern: `status-user-info`},
		},
	}},
	{Vendor: `Shieldon Firewall`, Manufacturer: `Shieldon.io`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `Please line up`},
			wafMatch{Kind: `content`, Name: ``, Pattern: `This page is limiting the number of people online. Please wait a moment.`},
		},
	}},
	{Vendor: `Shield Security`, Manufacturer: `One Dollar Plugin`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `You were blocked by the Shield`},
		},
	}},
	{Vendor: `Shield Security`, Manufacturer: `One Dollar Plugin`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `remaining transgression\(s\) against this site`},
		},
	}},
	{Vendor: `SiteGround`, Manufacturer: `SiteGround`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `Our system thinks you might be a robot!`},
		},
	}},
	{Vendor: `SiteGround`, Manufacturer: `SiteGround`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `access is restricted due to a security rule`},
		},
	}},
	{Vendor: `SiteGuard`, Manufacturer: `EG Secure Solutions Inc.`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `Powered by SiteGuard`},
		},
	}},
	{Vendor: `SiteGuard`, Manufacturer: `EG Secure Solutions Inc.`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `The server refuse to browse the page`},
		},
	}},
	{Vendor: `Sitelock`, Manufacturer: `TrueShield`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `SiteLock will remember you`},
		},
	}},
	{Vendor: `Sitelock`, Manufacturer: `TrueShield`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `Sitelock is leader in Business Website Security Services`},
		},
	}},
	{Vendor: `Sitelock`, Manufacturer: `TrueShield`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `sitelock[_\-]shield([_\-]logo|[\-_]badge)?`},
		},
	}},
	{Vendor: `Sitelock`, Manufacturer: `TrueShield`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `SiteLock incident ID`},
		},
	}},
	{Vendor: `SonicWall`, Manufacturer: `Dell`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `Server`, Pattern: `SonicWALL`},
		},
	}},
	{Vendor: `SonicWall`, Manufacturer: `Dell`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `<(title|h\d{1})>Web Site Blocked`},
		},
	}},
	{Vendor: `SonicWall`, Manufacturer: `Dell`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `\+?nsa_banner`},
		},
	}},
	{Vendor: `UTM Web Protection`, Manufacturer: `Sophos`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `www\.sophos\.com`},
		},
	}},
	{Vendor: `UTM Web Protection`, Manufacturer: `Sophos`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `Powered by.?(Sophos)? UTM Web Protection`},
		},
	}},
	{Vendor: `UTM Web Protection`, Manufacturer: `Sophos`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `<title>Access to the requested URL was blocked`},
			wafMatch{Kind: `content`, Name: ``, Pattern: `Access to the requested URL was blocked`},
			wafMatch{Kind: `content`, Name: ``, Pattern: `incident was logged with the following log identifier`},
			wafMatch{Kind: `content`, Name: ``, Pattern: `Inbound Anomaly Score exceeded`},
			wafMatch{Kind: `content`, Name: ``, Pattern: `Your cache administrator is`},
		},
	}},
	{Vendor: `Squarespace`, Manufacturer: `Squarespace`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `Server`, Pattern: `Squarespace`},
		},
	}},
	{Vendor: `Squarespace`, Manufacturer: `Squarespace`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `cookie`, Name: ``, Pattern: `^SS_ANALYTICS_ID=`},
		},
	}},
	{Vendor: `Squarespace`, Manufacturer: `Squarespace`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `cookie`, Name: ``, Pattern: `^SS_MATTR=`},
		},
	}},
	{Vendor: `Squarespace`, Manufacturer: `Squarespace`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `cookie`, Name: ``, Pattern: `^SS_MID=`},
		},
	}},
	{Vendor: `Squarespace`, Manufacturer: `Squarespace`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `cookie`, Name: ``, Pattern: `SS_CVT=`},
		},
	}},
	{Vendor: `Squarespace`, Manufacturer: `Squarespace`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `status\.squarespace\.com`},
		},
	}},
	{Vendor: `Squarespace`, Manufacturer: `Squarespace`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `BRICK\-\d{2}`},
		},
	}},
	{Vendor: `SquidProxy IDS`, Manufacturer: `SquidProxy`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `Server`, Pattern: `squid(/[0-9\.]+)?`},
			wafMatch{Kind: `content`, Name: ``, Pattern: `Access control configuration prevents your request`},
		},
	}},
	{Vendor: `StackPath`, Manufacturer: `StackPath`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `<title>StackPath[^<]+</title>`},
		},
	}},
	{Vendor: `StackPath`, Manufacturer: `StackPath`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `is using a security service for protection against online attacks`},
			wafMatch{Kind: `content`, Name: ``, Pattern: `An action has triggered the service and blocked your request`},
		},
	}},
	{Vendor: `Sucuri CloudProxy`, Manufacturer: `Sucuri Inc.`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `X-Sucuri-ID`, Pattern: `.+?`},
		},
	}},
	{Vendor: `Sucuri CloudProxy`, Manufacturer: `Sucuri Inc.`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `X-Sucuri-Cache`, Pattern: `.+?`},
		},
	}},
	{Vendor: `Sucuri CloudProxy`, Manufacturer: `Sucuri Inc.`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `Server`, Pattern: `Sucuri(\-Cloudproxy)?`},
		},
	}},
	{Vendor: `Sucuri CloudProxy`, Manufacturer: `Sucuri Inc.`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `X-Sucuri-Block`, Pattern: `.+?`},
		},
	}},
	{Vendor: `Sucuri CloudProxy`, Manufacturer: `Sucuri Inc.`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `Access Denied.{0,6}?Sucuri Website Firewall`},
		},
	}},
	{Vendor: `Sucuri CloudProxy`, Manufacturer: `Sucuri Inc.`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `<title>Sucuri WebSite Firewall.{0,6}?(CloudProxy)?.{0,6}?Access Denied`},
		},
	}},
	{Vendor: `Sucuri CloudProxy`, Manufacturer: `Sucuri Inc.`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `sucuri\.net/privacy\-policy`},
		},
	}},
	{Vendor: `Sucuri CloudProxy`, Manufacturer: `Sucuri Inc.`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `cdn\.sucuri\.net/sucuri[-_]firewall[-_]block\.css`},
		},
	}},
	{Vendor: `Sucuri CloudProxy`, Manufacturer: `Sucuri Inc.`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `cloudproxy@sucuri\.net`},
		},
	}},
	{Vendor: `Tencent Cloud Firewall`, Manufacturer: `Tencent Technologies`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `waf\.tencent\-?cloud\.com/`},
		},
	}},
	{Vendor: `Tencent Cloud Firewall`, Manufacturer: `Tencent Technologies`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `window\.location\.href.{1,3}?https?://waf.tencent(?:-?cloud)?.com/(?:403|501)page\.html`},
		},
	}},
	{Vendor: `Teros`, Manufacturer: `Citrix Systems`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `cookie`, Name: ``, Pattern: `^st8id=`},
		},
	}},
	{Vendor: `ThreatX`, Manufacturer: `A10 Networks`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `X-Request-Id`, Pattern: `.*`},
			wafMatch{Kind: `content`, Name: ``, Pattern: `Forbidden - ID: ([a-fA-F0-9]{32})`},
			wafMatch{Kind: `status`, Name: `403`, Pattern: ``},
		},
	}},
	{Vendor: `TransIP Web Firewall`, Manufacturer: `TransIP`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `X-TransIP-Backend`, Pattern: `.+`},
		},
	}},
	{Vendor: `TransIP Web Firewall`, Manufacturer: `TransIP`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `X-TransIP-Balancer`, Pattern: `.+`},
		},
	}},
	{Vendor: `UEWaf`, Manufacturer: `UCloud`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `Server`, Pattern: `uewaf(/[0-9\.]+)?`},
		},
	}},
	{Vendor: `UEWaf`, Manufacturer: `UCloud`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `/uewaf_deny_pages/default/img/`},
		},
	}},
	{Vendor: `UEWaf`, Manufacturer: `UCloud`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `ucloud\.cn`},
		},
	}},
	{Vendor: `URLMaster SecurityCheck`, Manufacturer: `iFinity/DotNetNuke`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `X-UrlMaster-Debug`, Pattern: `.+`},
		},
	}},
	{Vendor: `URLMaster SecurityCheck`, Manufacturer: `iFinity/DotNetNuke`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `X-UrlMaster-Ex`, Pattern: `.+`},
		},
	}},
	{Vendor: `URLMaster SecurityCheck`, Manufacturer: `iFinity/DotNetNuke`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `Ur[li]RewriteModule`},
			wafMatch{Kind: `content`, Name: ``, Pattern: `SecurityCheck`},
		},
	}},
	{Vendor: `URLScan`, Manufacturer: `Microsoft`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `Rejected[-_]By[_-]UrlScan`},
		},
	}},
	{Vendor: `URLScan`, Manufacturer: `Microsoft`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `A custom filter or module.{0,4}?such as URLScan`},
		},
	}},
	{Vendor: `Variti`, Manufacturer: `Variti`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `Server`, Pattern: `Variti(?:\/[a-z0-9\.\-]+)?`},
		},
	}},
	{Vendor: `Varnish`, Manufacturer: `OWASP`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `Request rejected by xVarnish\-WAF`},
		},
	}},
	{Vendor: `Vercel WAF`, Manufacturer: `Vercel`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `<title>Vercel Security Checkpoint</title>`},
		},
	}},
	{Vendor: `Vercel WAF`, Manufacturer: `Vercel`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `/vercel/security/`},
		},
	}},
	{Vendor: `Viettel`, Manufacturer: `Cloudrity`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `Access Denied.{0,10}?Viettel WAF`},
		},
	}},
	{Vendor: `Viettel`, Manufacturer: `Cloudrity`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `cloudrity\.com\.(vn)?/`},
		},
	}},
	{Vendor: `Viettel`, Manufacturer: `Cloudrity`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `Viettel WAF System`},
		},
	}},
	{Vendor: `VirusDie`, Manufacturer: `VirusDie LLC`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `cdn\.virusdie\.ru/splash/firewallstop\.png`},
		},
	}},
	{Vendor: `VirusDie`, Manufacturer: `VirusDie LLC`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `copy.{0,10}?Virusdie\.ru`},
		},
	}},
	{Vendor: `Wallarm`, Manufacturer: `Wallarm Inc.`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `Server`, Pattern: `nginx[\-_]wallarm`},
		},
	}},
	{Vendor: `WatchGuard`, Manufacturer: `WatchGuard Technologies`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `Server`, Pattern: `WatchGuard`},
		},
	}},
	{Vendor: `WatchGuard`, Manufacturer: `WatchGuard Technologies`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `Request denied by WatchGuard Firewall`},
		},
	}},
	{Vendor: `WatchGuard`, Manufacturer: `WatchGuard Technologies`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `WatchGuard Technologies Inc\.`},
		},
	}},
	{Vendor: `WebARX`, Manufacturer: `WebARX Security Solutions`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `WebARX.{0,10}?Web Application Firewall`},
		},
	}},
	{Vendor: `WebARX`, Manufacturer: `WebARX Security Solutions`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `www\.webarxsecurity\.com`},
		},
	}},
	{Vendor: `WebARX`, Manufacturer: `WebARX Security Solutions`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `/wp\-content/plugins/webarx/includes/`},
		},
	}},
	{Vendor: `WebKnight`, Manufacturer: `AQTRONIX`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `status`, Name: `999`, Pattern: ``},
			wafMatch{Kind: `reason`, Name: ``, Pattern: `No Hacking`},
		},
	}},
	{Vendor: `WebKnight`, Manufacturer: `AQTRONIX`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `status`, Name: `404`, Pattern: ``},
			wafMatch{Kind: `reason`, Name: ``, Pattern: `Hack Not Found`},
		},
	}},
	{Vendor: `WebKnight`, Manufacturer: `AQTRONIX`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `WebKnight Application Firewall Alert`},
		},
	}},
	{Vendor: `WebKnight`, Manufacturer: `AQTRONIX`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `What is webknight\?`},
		},
	}},
	{Vendor: `WebKnight`, Manufacturer: `AQTRONIX`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `AQTRONIX WebKnight is an application firewall`},
		},
	}},
	{Vendor: `WebKnight`, Manufacturer: `AQTRONIX`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `WebKnight will take over and protect`},
		},
	}},
	{Vendor: `WebKnight`, Manufacturer: `AQTRONIX`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `aqtronix\.com/WebKnight`},
		},
	}},
	{Vendor: `WebKnight`, Manufacturer: `AQTRONIX`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `AQTRONIX.{0,10}?WebKnight`},
		},
	}},
	{Vendor: `WebLand`, Manufacturer: `WebLand`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `Server`, Pattern: `protected by webland`},
		},
	}},
	{Vendor: `RayWAF`, Manufacturer: `WebRay Solutions`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `Server`, Pattern: `WebRay\-WAF`},
		},
	}},
	{Vendor: `RayWAF`, Manufacturer: `WebRay Solutions`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `DrivedBy`, Pattern: `RaySrv.RayEng/[0-9\.]+?`},
		},
	}},
	{Vendor: `WebSEAL`, Manufacturer: `IBM`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `Server`, Pattern: `WebSEAL`},
		},
	}},
	{Vendor: `WebSEAL`, Manufacturer: `IBM`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `This is a WebSEAL error message template file`},
		},
	}},
	{Vendor: `WebSEAL`, Manufacturer: `IBM`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `WebSEAL server received an invalid HTTP request`},
		},
	}},
	{Vendor: `WebTotem`, Manufacturer: `WebTotem`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `The current request was blocked.{0,8}?>WebTotem`},
		},
	}},
	{Vendor: `West263 CDN`, Manufacturer: `West263CDN`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `X-Cache`, Pattern: `WS?T263CDN`},
		},
	}},
	{Vendor: `Wordfence`, Manufacturer: `Defiant`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `Server`, Pattern: `wf[_\-]?WAF`},
		},
	}},
	{Vendor: `Wordfence`, Manufacturer: `Defiant`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `Generated by Wordfence`},
		},
	}},
	{Vendor: `Wordfence`, Manufacturer: `Defiant`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `broke one of (the )?Wordfence (advanced )?blocking rules`},
		},
	}},
	{Vendor: `Wordfence`, Manufacturer: `Defiant`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `/plugins/wordfence`},
		},
	}},
	{Vendor: `wpmudev WAF`, Manufacturer: `Incsub`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `Click on the Logs tab, then the WAF Log.`},
			wafMatch{Kind: `content`, Name: ``, Pattern: `Choose your site from the list`},
			wafMatch{Kind: `status`, Name: `403`, Pattern: ``},
		},
	}},
	{Vendor: `wpmudev WAF`, Manufacturer: `Incsub`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `<h1>Whoops, this request has been blocked!`},
			wafMatch{Kind: `content`, Name: ``, Pattern: `This request has been deemed suspicious`},
			wafMatch{Kind: `content`, Name: ``, Pattern: `possible attack on our servers.`},
			wafMatch{Kind: `status`, Name: `403`, Pattern: ``},
		},
	}},
	{Vendor: `WTS-WAF`, Manufacturer: `WTS`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `Server`, Pattern: `wts/[0-9\.]+?`},
		},
	}},
	{Vendor: `WTS-WAF`, Manufacturer: `WTS`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `<(title|h\d{1})>WTS\-WAF`},
		},
	}},
	{Vendor: `360WangZhanBao`, Manufacturer: `360 Technologies`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `Server`, Pattern: `qianxin\-waf`},
		},
	}},
	{Vendor: `360WangZhanBao`, Manufacturer: `360 Technologies`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `WZWS-Ray`, Pattern: `.+?`},
		},
	}},
	{Vendor: `360WangZhanBao`, Manufacturer: `360 Technologies`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `X-Powered-By-360WZB`, Pattern: `.+?`},
		},
	}},
	{Vendor: `360WangZhanBao`, Manufacturer: `360 Technologies`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `wzws\-waf\-cgi/`},
		},
	}},
	{Vendor: `360WangZhanBao`, Manufacturer: `360 Technologies`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `wangshan\.360\.cn`},
		},
	}},
	{Vendor: `360WangZhanBao`, Manufacturer: `360 Technologies`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `status`, Name: `493`, Pattern: ``},
		},
	}},
	{Vendor: `XLabs Security WAF`, Manufacturer: `XLabs`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `X-CDN`, Pattern: `XLabs Security`},
		},
	}},
	{Vendor: `XLabs Security WAF`, Manufacturer: `XLabs`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `Secured`, Pattern: `^By XLabs Security`},
		},
	}},
	{Vendor: `XLabs Security WAF`, Manufacturer: `XLabs`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `Server`, Pattern: `XLabs[-_]?.?WAF`},
		},
	}},
	{Vendor: `Xuanwudun`, Manufacturer: `Xuanwudun`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `admin\.dbappwaf\.cn/(index\.php/Admin/ClientMisinform/)?`},
		},
	}},
	{Vendor: `Xuanwudun`, Manufacturer: `Xuanwudun`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `class=.(db[\-_]?)?waf(.)?([\-_]?row)?>`},
		},
	}},
	{Vendor: `Yundun`, Manufacturer: `Yundun`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `Server`, Pattern: `YUNDUN`},
		},
	}},
	{Vendor: `Yundun`, Manufacturer: `Yundun`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `X-Cache`, Pattern: `YUNDUN`},
		},
	}},
	{Vendor: `Yundun`, Manufacturer: `Yundun`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `cookie`, Name: ``, Pattern: `^yd_cookie=`},
		},
	}},
	{Vendor: `Yundun`, Manufacturer: `Yundun`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `Blocked by YUNDUN Cloud WAF`},
		},
	}},
	{Vendor: `Yundun`, Manufacturer: `Yundun`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `yundun\.com/yd[-_]http[_-]error/`},
		},
	}},
	{Vendor: `Yundun`, Manufacturer: `Yundun`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `www\.yundun\.com/(static/js/fingerprint\d{1}?\.js)?`},
		},
	}},
	{Vendor: `Yunsuo`, Manufacturer: `Yunsuo`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `cookie`, Name: ``, Pattern: `^yunsuo_session=`},
		},
	}},
	{Vendor: `YXLink`, Manufacturer: `YxLink Technologies`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `cookie`, Name: ``, Pattern: `^yx_ci_session=`},
		},
	}},
	{Vendor: `YXLink`, Manufacturer: `YxLink Technologies`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `cookie`, Name: ``, Pattern: `^yx_language=`},
		},
	}},
	{Vendor: `YXLink`, Manufacturer: `YxLink Technologies`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `Server`, Pattern: `Yxlink([\-_]?WAF)?`},
		},
	}},
	{Vendor: `Zenedge`, Manufacturer: `Zenedge`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `Server`, Pattern: `ZENEDGE`},
		},
	}},
	{Vendor: `Zenedge`, Manufacturer: `Zenedge`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `X-Zen-Fury`, Pattern: `.+?`},
		},
	}},
	{Vendor: `Zenedge`, Manufacturer: `Zenedge`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `/__zenedge/`},
		},
	}},
	{Vendor: `ZScaler`, Manufacturer: `Accenture`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `header`, Name: `Server`, Pattern: `ZScaler`},
		},
	}},
	{Vendor: `ZScaler`, Manufacturer: `Accenture`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `Access Denied.{0,10}?Accenture Policy`},
		},
	}},
	{Vendor: `ZScaler`, Manufacturer: `Accenture`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `policies\.accenture\.com`},
		},
	}},
	{Vendor: `ZScaler`, Manufacturer: `Accenture`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `login\.zscloud\.net/img_logo_new1\.png`},
		},
	}},
	{Vendor: `ZScaler`, Manufacturer: `Accenture`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `Zscaler to protect you from internet threats`},
		},
	}},
	{Vendor: `ZScaler`, Manufacturer: `Accenture`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `Internet Security by ZScaler`},
		},
	}},
	{Vendor: `ZScaler`, Manufacturer: `Accenture`, Groups: [][]wafMatch{
		[]wafMatch{
			wafMatch{Kind: `content`, Name: ``, Pattern: `Accenture.{0,10}?webfilters indicate that the site likely contains`},
		},
	}},
}
