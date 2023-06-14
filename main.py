import imaplib
import email
import smtplib
import ssl
import time
from itertools import chain
import re
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import dns.resolver
from nacl.public import PrivateKey, Box
import pandas as pd
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.model_selection import train_test_split

class check_mail:

    def first_login(self):
        # login to the imap
        mail = imaplib.IMAP4_SSL(imap_ssl_host)
        mail.login(EMAIL, PASSWORD)
        # select the folder
        mail.select('inbox')

    def search_string(self, uid_max, criteria):
        c = list(map(lambda t: (t[0], '"' + str(t[1]) + '"'), criteria.items())) + [('UID', '%d:*' % (uid_max + 1))]

        return '(%s)' % ' '.join(chain(*c))


    # login to the imap
    def check_email_uid(self,uid_max,criteria):

        mail = imaplib.IMAP4_SSL(imap_ssl_host)
        mail.login(EMAIL, PASSWORD)
        mail.select('inbox')

        result, data = mail.uid('SEARCH', None, check_mail.search_string(self,uid_max, criteria))
        uids = [int(s) for s in data[0].split()]
        if uids:
            uid_max = max(uids)

        # Logout before running the while loop
        print(uid_max)
        mail.logout()
        return uid_max ,result,data



    def send_to_admin(self,body):
        with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context) as smtp:
            smtp.login(EMAIL, PASSWORD)
            box = Box(private_key, public_key)
            message = MIMEMultipart()

            subject = "Zablokowana  wiadomość spamowa"
            body = f"Wiadomość spamowa o temacie: {body}"
            message["Subject"] = subject
            # # ciphertext = bytes(message.decode('utf-8'))
            # encrypted = box.encrypt(body.encode('utf-8'))
            # # message = MIMEText(body.encode('utf-8'), 'plain', 'utf-8')
            # encrypted_str = base64.b64encode(encrypted.ciphertext).decode('utf-8')
            message.attach(MIMEText(body, 'plain'))
            smtp.sendmail(EMAIL, "admin_email@gmail.com", message.as_string())
            print("wysłana")


    def check_spam(self,subject,mail,uid,test_set):

        raw_email = subject
        body = raw_email
        email_message = email.message_from_string(raw_email)

        if subject.upper() == 'SPAM':
            mail.uid('STORE', str(uid), '+FLAGS', '(\Deleted)')
            mail.expunge()
            print('Blocked SPAM message:', subject)
            check_mail.send_to_admin(self,body)


        if test_set.loc[test_set['email'] == email_message.get_payload(), 'spam'].values:
            mail.store('STORE', str(uid), '+FLAGS', '\\Deleted')
            check_mail.send_to_admin(self,body)

    def check_server(self,adress_email):

        server = smtplib.SMTP()

        blacklists = ['zen.spamhaus.org', 'bl.spamcop.net']

        to_address = re.search(r'(<.+>)', adress_email)

        to_address = to_address.group()
        email_address = to_address.strip('<>')

        print(email_address)

        domain = email_address.split("@")[1]
        print(domain)

        answers = dns.resolver.resolve(domain, 'MX')
        print(answers)

        mx_record = str(answers[0].exchange)

        s = dns.resolver.resolve(mx_record, 'A')
        ip_address = str(s[0])
        for blacklist in blacklists:
            query = '.'.join(str(ip_address).split('.')) + '.' + blacklist
            print(query)
            try:
                answers = dns.resolver.query(query, 'A')
                print(answers)
            except dns.resolver.NXDOMAIN:
                print("IP is safe")
            else:
                print("IP is on black_list")

        server.connect(mx_record)
        print(server.connect(mx_record))
        server.helo(server.local_hostname)
        print(server.helo(server.local_hostname))

        server.mail(email_address)
        print(server.mail(email_address))
        code, message = server.rcpt(str(email_address))
        print(server.rcpt(str(email_address)))
        print("code:", code)
        print("message:", message)
        server.quit()

    def check_email(self,uid_max,criteria,test_set):

        while 1:
            mail = imaplib.IMAP4_SSL(imap_ssl_host)
            mail.login(EMAIL, PASSWORD)
            mail.select('inbox')
            result, data = mail.uid('search', None, check_mail.search_string(self,uid_max, criteria))
            uids = [int(s) for s in data[0].split()]

            for uid in uids:
                # Have to check again because Gmail sometimes does not obey UID criterion.
                if uid > uid_max:
                    result, data = mail.uid('fetch', str(uid), '(RFC822)')
                    for response_part in data:
                        if isinstance(response_part, tuple):
                            # message_from_string can also be use here

                            msg = email.message_from_bytes(response_part[1])
                            subject = msg['subject']
                            adress_email = msg.get('From')
                            payload = msg.get_payload()

                            if isinstance(payload, list):

                                body = (''.join([part.get_payload(decode=True).decode() for part in payload]))
                                pattern = r'<div dir="ltr">(.*?)</div>'
                                match = re.search(pattern, body)
                                if match:
                                    body = match.group(1)
                            else:

                                body = payload.get_payload(decode=True).decode()




                            check_mail.check_server(self,adress_email)
                            check_mail.check_spam(self,subject,mail,uid,test_set)

                uid_max = uid
            mail.logout()


            time.sleep(1)



        print("func2: finishing")

if __name__ == '__main__':
    criteria = {}
    uid_max = 0

    EMAIL = "user_email@gmail.com"
    PASSWORD = "SMTP_SERVER_PASSWORD"
    SMTP_SERVER = "imap.gmail.com"
    SMTP_PORT = 993
    imap_ssl_host = 'imap.gmail.com'
    smtp_server = "smtp.gmail.com"

    # Tworzenie kontekstu SSL
    context = ssl.create_default_context()

    dns.resolver.default_resolver = dns.resolver.Resolver(configure=False)
    dns.resolver.default_resolver.nameservers = ['8.8.8.8']

    private_key = PrivateKey.generate()
    public_key = private_key.public_key

    with open('private_key.bin', 'wb') as f:
        f.write(bytes(private_key))

    # Zapisywanie klucza publicznego do pliku
    with open('public_key.bin', 'wb') as f:
        f.write(bytes(public_key))
    # Funkcja do sprawdzania wiadomości
    data = pd.read_csv('spam.csv').drop('label_num', axis=1)

    data['text'] = data['text'].str.replace('<[^<>]+>', '')

    X_train, X_test, y_train, y_test = train_test_split(data['text'], data['label'], test_size=0.2, random_state=42)

    vectorizer = CountVectorizer()
    X_train_vect = vectorizer.fit_transform(X_train)
    X_test_vect = vectorizer.transform(X_test)

    # Train the model
    model = MultinomialNB()
    model.fit(X_train_vect, y_train)

    # Test the model
    y_pred = model.predict(X_test_vect)

    test_set = pd.DataFrame({'email': X_test.reset_index(drop=True), 'label': y_pred})

    #  spam emails
    test_set.loc[test_set['label'] == 1, 'spam'] = True
    test_set.loc[test_set['label'] == 0, 'spam'] = False

    c = check_mail()
    c.first_login()
    c.search_string(uid_max,criteria)
    uid_max = c.check_email_uid(uid_max,criteria)
    uid_max=uid_max[0]

    c.check_email(uid_max,criteria,test_set)






