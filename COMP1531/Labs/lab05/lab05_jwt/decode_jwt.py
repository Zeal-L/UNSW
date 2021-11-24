
import jwt


encode_jwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1X2lkIjoiMTIzNDUifQ.lBTAPFU1xxDAi2Vrusfo67ypBai0vBr6O7KOt6CJf1s'

decoded = jwt.decode(encode_jwt, 'comp1531', algorithms = ['HS256'], options={"verify_signature": False})

print(decoded)