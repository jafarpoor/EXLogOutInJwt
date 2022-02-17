using System;
using Microsoft.EntityFrameworkCore.Migrations;

namespace EXJWT.Migrations
{
    public partial class refresh : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "RefrshToken",
                table: "UserTokens",
                type: "nvarchar(max)",
                nullable: true);

            migrationBuilder.AddColumn<DateTime>(
                name: "RefrshTokenExp",
                table: "UserTokens",
                type: "datetime2",
                nullable: false,
                defaultValue: new DateTime(1, 1, 1, 0, 0, 0, 0, DateTimeKind.Unspecified));
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "RefrshToken",
                table: "UserTokens");

            migrationBuilder.DropColumn(
                name: "RefrshTokenExp",
                table: "UserTokens");
        }
    }
}
