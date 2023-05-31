from bs4 import BeautifulSoup
import pandas as pd 

def slugify(name):
    tr2eng = str.maketrans("çÇğĞıİöÖşŞüÜ", "ccggiioossuu")
    eng = name.translate(tr2eng)
    return eng

output  = []

html = open("linkedin.html", "r", encoding='utf-8').read()
soup = BeautifulSoup(html, 'lxml')

peoples = soup.find_all('div', {'class' : 'org-people-profile-card__profile-info'})

for people in peoples:
    name = people.find('div', {'class' : 'artdeco-entity-lockup__title ember-view'}).text.strip()
    position = people.find('div', {'class' : 'artdeco-entity-lockup__subtitle ember-view'}).text.strip()

    if name == 'LinkedIn Member': continue
    mail = slugify(name.lower())
    mail = mail.split(' ')[0] + '.' + mail.split(' ')[-1]

    output.append((name, mail, position))


pd.DataFrame(output, columns=['name', 'mail', 'position']).to_excel('linkedin.xlsx', index = False)