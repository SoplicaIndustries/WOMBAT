using AutoMapper;

namespace WOMBAT.Models
{
    public class MappingProfile : Profile
    {
        public MappingProfile()
        {
            CreateMap<ViewUser, User>()
                .ForMember(u => u.UserName, opt => opt.MapFrom(x => x.Username))
                .ForMember(u => u.Email, opt => opt.MapFrom(x => x.Mail))
               
                ;

        }
    }
}
