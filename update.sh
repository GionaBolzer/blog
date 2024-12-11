#!/bin/bash
hugo
tar -cvf public.tar public/ 
scp public.tar blog:/var/www/ 
ssh blog 'cd /var/www;tar -xvf public.tar;chown -R www-data:www-data public/;rm -rf public.tar'
rm -r public.tar
