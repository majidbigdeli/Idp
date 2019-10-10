using System;
using Microsoft.EntityFrameworkCore.Migrations;

namespace Manex.Authentication.Migrations
{
    public partial class InitMajid2 : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "AccountExpires",
                table: "AppUsers");

            migrationBuilder.DropColumn(
                name: "DataEventRecordsRole",
                table: "AppUsers");

            migrationBuilder.DropColumn(
                name: "IsAdmin",
                table: "AppUsers");

            migrationBuilder.DropColumn(
                name: "SecuredFilesRole",
                table: "AppUsers");
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<DateTime>(
                name: "AccountExpires",
                table: "AppUsers",
                nullable: false,
                defaultValue: new DateTime(1, 1, 1, 0, 0, 0, 0, DateTimeKind.Unspecified));

            migrationBuilder.AddColumn<string>(
                name: "DataEventRecordsRole",
                table: "AppUsers",
                nullable: true);

            migrationBuilder.AddColumn<bool>(
                name: "IsAdmin",
                table: "AppUsers",
                nullable: false,
                defaultValue: false);

            migrationBuilder.AddColumn<string>(
                name: "SecuredFilesRole",
                table: "AppUsers",
                nullable: true);
        }
    }
}
