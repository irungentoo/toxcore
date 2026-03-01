# vim:ft=dockerfile
FROM toxchat/c-toxcore:coverage AS build
FROM nginx:alpine
COPY --from=build --chown=nginx:nginx /work/_build/html/ /usr/share/nginx/html/
