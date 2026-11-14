const _=require('lodash');const express=require('express');const app=express();app.get('/',(q,r)=>r.send(_.join(['ok'])));app.listen(3000);
