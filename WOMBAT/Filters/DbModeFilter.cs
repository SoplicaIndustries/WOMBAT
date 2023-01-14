using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;

namespace WOMBAT.Filters
{
    public class DbModeFilter : IActionFilter
    {
        public void OnActionExecuted(ActionExecutedContext context)
        {
        }

        public void OnActionExecuting(ActionExecutingContext context)
        {
            var config = context.HttpContext.RequestServices.GetRequiredService<IConfiguration>();
            if (!config.GetValue<bool>("JWT:DbMode"))
            {
                context.Result = new ContentResult()
                {
                    StatusCode = 404
                };
                return;
            }
        }
    }
}
