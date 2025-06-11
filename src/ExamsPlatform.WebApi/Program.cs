using ExamsPlatform.Infrastructure.Database;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();
builder.Services.AddDatabase(builder.Configuration);


var app = builder.Build();

app.MapControllers();

app.Run();
