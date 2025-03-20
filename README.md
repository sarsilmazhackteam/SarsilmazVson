**Sarsılmaz Güvenlik Tarama Aracı**, web uygulamalarında yaygın güvenlik açıklarını tespit etmek için geliştirilmiş bir güvenlik tarama aracıdır. Bu araç, komut enjeksiyonu, açık dizinler, dosya dahil etme, XSS, CSRF, dosya yükleme açıkları gibi birçok güvenlik zafiyetini tespit etmek için kullanılabilir. Ayrıca, WAF tespiti ve SQLMap entegrasyonu ile veritabanı taraması yapabilir.

Bu proje, Sarsılmaz Team adı altında **Emin Sarsılmaz** tarafından kodlanmıştır.

# Özellikler
• Komut Enjeksiyonu Testi: Web uygulamasında komut enjeksiyonu açıklarını tespit eder.

• Açık Dizin Testi: Web sunucusunda açık dizinlerin olup olmadığını kontrol eder.

• Dosya Dahil Etme Testi: Dosya dahil etme açıklarını tespit eder.

• XSS Testi: Cross-Site Scripting (XSS) açıklarını tespit eder.

• CSRF Testi: Cross-Site Request Forgery (CSRF) korumasını kontrol eder.

• Dosya Yükleme Testi: Dosya yükleme açıklarını tespit eder.

• WAF Tespiti: Web uygulaması güvenlik duvarı (WAF) olup olmadığını tespit eder.

• SQLMap Entegrasyonu: SQLMap ile veritabanı taraması yapar.

• Port Tarama: Hedef sunucuda açık portları tarar.

# Kurulum
Gereksinimler: Python 3.x ve aşağıdaki Python kütüphaneleri gereklidir:

• requests

• urllib

• termcolor

• pyfiglet

• colorama

Kütüphanelerin Kurulumu:

**pip install requests termcolor pyfiglet colorama**

SQLMap Kurulumu:

*SQLMap'in sisteminizde kurulu olduğundan emin olun. SQLMap'i resmi GitHub sayfasından indirebilirsiniz.*

Aracı İndirme:

Bu projeyi GitHub'dan klonlayın:

**git clone https://github.com/sarsilmazhackteam/SarsilmazVson.git**

**cd SarsilmazVson**

Aracı Çalıştırma:

Aracı çalıştırmak için aşağıdaki komutu kullanın:

**python sarsilmaz.py**

Taranacak URL'yi Girme:

Aracı çalıştırdıktan sonra, taranacak URL'yi girin. Örneğin:

**[?] Taranacak URL: http://example.com**

## Gerisinide bi zahmet anlayın...
