using EducationCenter.Core.RepositoryContracts;
using ExamsPlatform.Infrastructure.Database;
using ExamsPlatform.Core.Entities;

namespace ExamsPlatform.Infrastructure.Repositories;

public class UserRepository : Repository<User>, IUserRepository
{
    public UserRepository(AppDbContext appDbContext) : base(appDbContext)
    {
    }

}
