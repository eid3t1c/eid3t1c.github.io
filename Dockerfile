
FROM ruby:3.2


RUN apt-get update -qq && apt-get install -y build-essential nodejs


WORKDIR /usr/src/app

RUN gem install bundler

COPY Gemfile Gemfile.lock ./

RUN bundle install


COPY . .


EXPOSE 4000

# Default command to serve the Jekyll blog
CMD ["bundle", "exec", "jekyll", "s"]
