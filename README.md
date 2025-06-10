Advanced Secure File Transfer System: Encryption, Low-Level IP Processing & Network Performance Analysis
Genel Bakış
Bu proje, ağ güvenliği ve ağ performansı prensiplerini uygulayarak güvenli ve performanslı bir dosya transfer sistemi geliştirmeyi hedeflemektedir. Sistem, hassas verilerin güvenli bir şekilde aktarılmasını sağlamak için gelişmiş şifreleme algoritmalarını (AES ve RSA) ve veri bütünlüğü doğrulaması için SHA-256 hash fonksiyonunu kullanmaktadır. Ayrıca, düşük seviye IP paket işleme yetenekleri (Scapy ile özelleştirilmiş IP başlıkları) ve kapsamlı ağ performans analizleri (Wireshark, iPerf3 ve ping araçlarıyla) bu projenin temel bileşenleridir.

Özellikler
1. Dosya Transfer Sistemi
Kontrol Kanalı (TCP): AES anahtarının paylaşımı, veri hash doğrulaması ve şifreli veri uzunluğunun iletilmesi için güvenilir TCP protokolü kullanılır.

Veri Kanalı (Raw IP): Şifreli veriler, Scapy kütüphanesi aracılığıyla özelleştirilmiş IP başlıkları (TTL, Flags) kullanılarak düşük seviye "raw IP" paketleri halinde, parçalı olarak gönderilir.

2. Güvenlik Mekanizmaları
Asimetrik Şifreleme (RSA-2048): Oturum anahtarı olan AES anahtarının güvenli bir şekilde iletilmesi için RSA-2048 algoritmasıyla anahtar çifti oluşturulur ve açık anahtar ile şifreleme yapılır.

Simetrik Şifreleme (AES-256-CBC): Gönderilecek dosya içeriği, güçlü AES-256-CBC algoritması kullanılarak şifrelenir.

Veri Bütünlüğü (SHA-256): Transfer edilen dosyanın bütünlüğü, SHA-256 hash fonksiyonu kullanılarak doğrulanır. Bu, verinin iletim sırasında herhangi bir değişikliğe uğramadığını garanti eder.

3. Düşük Seviye IP Başlık İşleme
Scapy Entegrasyonu: Scapy kütüphanesi kullanılarak IP paketlerinin TTL (Time To Live), Flags (DF - Don't Fragment bit) ve checksum değerleri manuel olarak ayarlanır ve yönetilir.

Parçalama ve Yeniden Birleştirme Simülasyonu: Veriler, belirli bir fragment_size değerine göre parçalanır ve sunucu tarafında bu parçalar toplanarak yeniden birleştirilir.

4. Ağ Performans Ölçümleri
Gecikme (RTT) Analizi: ping komutu ile ağ gecikmesi (Round Trip Time) ölçümleri yapılmıştır. Ortalama RTT süresi ve paket kaybı raporlanmıştır.

Bant Genişliği Analizi (iPerf3): iPerf3 aracı kullanılarak localhost ve gerçek Wi-Fi arayüzü üzerinde bant genişliği testleri gerçekleştirilmiştir. MacOS Network Link Conditioner gibi araçlarla zayıf ağ koşulları simüle edilmiştir.

Paket Analizi (Wireshark): Gönderilen IP paketleri Wireshark ile yakalanmış, "MYFILE" imzasıyla filtrelenmiş ve şifrelenmiş verinin okunamaz olduğu doğrulanmıştır.

Kurulum ve Çalıştırma
Bağımlılıklar
Bu projeyi çalıştırmak için aşağıdaki Python kütüphanelerine ve sistem araçlarına ihtiyacınız olacaktır:

Python 3.x

cryptography: pip install cryptography

scapy: pip install scapy

hashlib (Dahili Python modülü)

iPerf3 (Ağ performans analizi için)

Wireshark (Paket analizi için)

ping (Ağ gecikmesi testi için)

MacOS kullanıcıları için isteğe bağlı: Network Link Conditioner (Ağ koşulu simülasyonu için Apple Developer Tools ile birlikte gelir).

Proje Yapısı
.
├── client.py
├── server.py
├── testfile.txt
├── server_public.pem (sunucu ilk çalıştığında otomatik oluşur)
└── received_file.txt (sunucu tarafından alındığında oluşur)

Adımlar
Gerekli Kütüphaneleri Kurun:

pip install cryptography scapy

testfile.txt Oluşturun:
Göndermek istediğiniz içeriği içeren bir testfile.txt dosyası oluşturun veya mevcut testfile.txt dosyasını kullanın.

Bu bir test dosyasidir.
Proje icin ornek veri icerir.

Sunucuyu Başlatın:
server.py dosyasını çalıştırın. Bu, sunucunun RSA anahtar çiftini oluşturmasını ve server_public.pem dosyasını kaydetmesini sağlayacaktır. Ayrıca TCP bağlantılarını dinlemeye başlayacak ve ardından IP paketlerini yakalamak için hazır olacaktır.

python server.py

Not: Sunucuyu ilk kez çalıştırdığınızda server_public.pem dosyası otomatik olarak oluşturulacaktır.

client.py Dosyasını Güncelleyin:
client.py dosyasını açın ve server_ip değişkenini sunucunun IP adresiyle güncelleyin. Örneğin:

server_ip = "192.168.1.97" # Buraya sunucunun IP adresini yazın

İstemciyi Başlatın:
Sunucu çalışır durumdayken, ayrı bir terminalde client.py dosyasını çalıştırın. Bu, şifrelenmiş veriyi ve anahtarları sunucuya gönderecektir.

python client.py

Kullanım
İstemci (client.py), testfile.txt dosyasını şifreler, hash'ini hesaplar ve RSA ile şifrelenmiş AES anahtarını TCP üzerinden sunucuya gönderir.

Ardından şifreli veri, Scapy kullanılarak düşük seviyeli IP paketleri olarak gönderilir.

Sunucu (server.py), önce TCP üzerinden anahtar ve boyut bilgilerini alır, ardından IP paketlerini yakalar, AES anahtarını RSA ile çözer, veriyi şifresini çözer ve SHA-256 hash'ini doğrulayarak received_file.txt olarak kaydeder.

Kısıtlamalar ve Geliştirmeler
MacOS Loopback Arayüzü Sorunları: MacOS loopback arayüzünde IP paketlerinin yakalanması sırasında bazı sorunlar yaşanmıştır; gerçek fiziksel ağ üzerinde çalışma tavsiye edilir.

Test Ortamı Sınırlamaları: Ethernet ve VPN ortamlarında test gerçekleştirilememiştir; gelecekte farklı ortamlarla test yapılabilir.

MITM Atak Testleri: MITM (Man-in-the-Middle) atak testleri teorik olarak planlanmış, ancak pratik uygulama yapılmamıştır.

Gelecek Geliştirmeler: İleri aşamalarda bir grafik kullanıcı arayüzü (GUI) ve TCP/UDP hibrit dosya transfer özelliği gibi ek özelliklerin eklenmesi mümkündür.

Ekran Görüntüleri ve Dosyalar
Proje raporunda detaylı ekran görüntüleri ve oluşturulan dosyalar yer almaktadır:

Appendix B: Experimental Screenshots

iPerf3 Testi (Wi-Fi Network Link Conditioner altında)

iPerf3 Testi (Localhost testi)

Ping RTT Gecikme Testi (google.com’a yapılan ping testleri)

Wireshark Analizi (IP paketi yakalama, MYFILE imzası filtreleme)

Wireshark Analizi (Şifreli veri paketleri görünümü)

Appendix C: Generated Files

testfile.txt: Gönderilen orijinal veri.

server_public.pem: Sunucunun RSA açık anahtarı.

received_file.txt: Başarıyla alınan ve doğrulanmış dosya.

Referanslar
Scapy Documentation

Python Cryptography Documentation

iPerf3 Documentation

Wireshark Documentation

Apple Developer Documentation (Network Link Conditioner)

Yazar
ZEYNEP SUDE GÜNEŞ
22360859055
BİLGİSAYAR MÜHENDİSLİĞİ - 3.SINIF
BURSA TEKNİK ÜNİVERSİTESİ
Mühendislik ve Doğa Bilimleri Fakültesi – Bilgisayar Mühendisliği Bölümü
