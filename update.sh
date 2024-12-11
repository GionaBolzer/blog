#!/bin/bash
hugo
tar -cvf public.tar public/
scp -r public.tar blog:/var/www/
rm -rf public.tar