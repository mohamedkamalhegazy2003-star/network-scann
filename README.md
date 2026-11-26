# Network Scan

برنامج ويندوز بيتسطب لفحص الشبكة (واي فاي + كابل Ethernet):
- سبب بطء الشبكة (تشخيص + حلول مرتبة بالأولوية)
- الأجهزة المتصلة (IP / MAC / الاسم / النوع / المنافذ المفتوحة)
- قوة الإشارة (واي فاي) أو سرعة الوصلة وأخطاء الكابل (Ethernet)
- سرعة التحميل والرفع، Ping، Jitter، فقد الحزم، سرعة DNS
- الأمان: تشفير الواي فاي، منافذ خطرة، UPnP، الجدار الناري، البروكسي
- أزرار إصلاح: مسح DNS، تغيير DNS، تجديد IP، إصلاح Winsock
- واجهة عربي/English، وحفظ التقرير كملف نصي

## البناء
ارفع المحتوى لمستودع GitHub (فرع main) وهيشتغل Actions تلقائياً.
من تبويب Actions → آخر Run → Artifacts:
- `NetworkScan-Setup` : المثبّت (Setup)
- `NetworkScan-Portable` : ملف EXE مباشر

محلياً (ويندوز + .NET 8 SDK):
`dotnet publish -c Release -r win-x64 --self-contained -p:PublishSingleFile=true -o publish`
ثم افتح `installer/NetworkScan.iss` بـ Inno Setup.

> بعض أزرار الإصلاح (تغيير DNS وغيره) تحتاج تشغيل البرنامج كمسؤول.
