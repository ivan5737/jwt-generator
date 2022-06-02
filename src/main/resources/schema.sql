create table privateKey
(
   id varchar(255) not null,
   modulus varchar(800) not null,
   exponent varchar(800) not null,
   primary key(id)
);