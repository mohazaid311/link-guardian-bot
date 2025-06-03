import telebot
import requests

BOT_TOKEN = '7806220501:AAFfmigv2ACMQgR1_Ch9TCxpaifAf9oOHnQ'
VT_API_KEY = 'dd5580f876898843ba3d6fcea58e9cb8ef3ab43e0d8ef8e9838ceb865d6c2d81ا'

bot = telebot.TeleBot(BOT_TOKEN)

def check_link(url):
    api_url = 'https://www.virustotal.com/api/v3/urls'
    headers = {"x-apikey": VT_API_KEY}
    data = {"url": url}
    response = requests.post(api_url, headers=headers, data=data)
    if response.status_code == 200:
        link_id = response.json()['data']['id']
        report = requests.get(f"{api_url}/{link_id}", headers=headers)
        return report.json()
    else:
        return None

@bot.message_handler(func=lambda message: 'http' in message.text)
def handle_url(message):
    url = message.text.strip()
    result = check_link(url)
    if result and result['data']['attributes']['last_analysis_stats']['malicious'] > 0:
        bot.delete_message(message.chat.id, message.message_id)
        bot.send_message(message.chat.id, "⚠️ تم حذف رابط خبيث!")
    else:
        bot.send_message(message.chat.id, "✅ الرابط آمن.")

bot.polling()