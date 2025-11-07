FROM public.ecr.aws/lambda/python:3.9

RUN pip install \
    aws-encryption-sdk \
    pyarrow==14.0.2

#COPY app.py .
COPY . .

CMD ["app.handler"]