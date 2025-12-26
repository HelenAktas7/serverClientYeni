# AES – DES – RSA ile Şifreli İstemci–Sunucu Haberleşmesi

Bu proje, AES, DES ve RSA algoritmaları kullanılarak geliştirilen bir istemci–sunucu
şifreli haberleşme sistemini içermektedir. Amaç, simetrik ve asimetrik şifreleme
algoritmalarının birlikte kullanımını hem teorik hem de pratik olarak göstermektir.

 Proje Mimarisi
- **Frontend:** React  
- **Backend:** Flask (Python)  
- **İletişim:** HTTP (JSON payload)  
- **Analiz:** Wireshark  

##Kullanılan Şifreleme Yöntemleri

### AES-128 (Kütüphaneli)
- Simetrik şifreleme algoritmasıdır.
- Mesaj AES-128 ile şifrelenir.
- AES anahtarı RSA ile şifrelenerek sunucuya gönderilir.

###  DES (Kütüphaneli)
- Simetrik şifreleme algoritmasıdır.
- AES’e kıyasla daha kısa anahtar ve daha küçük paket boyutları üretir.
- Anahtar dağıtımı RSA ile sağlanır.

###  RSA (Asimetrik)
- Bu projede doğrudan mesaj şifrelemek için değil,
  AES/DES anahtarlarının güvenli iletimi için kullanılmıştır.
- RSA ile şifrelenen `encrypted_key` alanının paket boyutunun
  simetrik algoritmalara göre daha büyük olduğu gözlemlenmiştir.

###  Manuel DES (Kütüphanesiz)
- DES algoritmasının basitleştirilmiş Feistel yapısı kullanılarak
  manuel olarak implement edilmiştir.
- XOR tabanlı işlemler ve sabit tur sayısı kullanılmıştır.
- Eğitsel amaçlıdır, gerçek sistemler için güvenli değildir.

### Wireshark Analizi
- Tüm şifreli mesajlar TCP paketleri içinde okunamaz (ciphertext) olarak taşınmaktadır.
- Payload içeriği düz metin içermemektedir.
- AES-128 paketlerinin TCP `Length` değeri DES’e göre daha büyüktür.
- RSA ile şifrelenen anahtar (`encrypted_key`) alanı, simetrik algoritmalara göre
  daha büyük veri üretmektedir.