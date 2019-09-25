FROM mcr.microsoft.com/dotnet/core/sdk:2.2 AS build-env
COPY . /app
WORKDIR /app
RUN ["dotnet","restore","./Manex.Authentication.csproj"]
RUN ["dotnet","build","./Manex.Authentication.csproj"]
EXPOSE 5000/tcp
ENTRYPOINT [ "dotnet", "watch", "run", "--no-restore", "--urls", "https://0.0.0.0:5000"]