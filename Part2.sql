---SQL


create table if not exists Employees
(
    id            int,
    first_name    varchar,
    last_name     varchar,
    hire_date     date,
    salary        int,
    manager_id    int,
    department_id int
);

create table if not exists Departments
(
    id   int,
    name varchar
);

------------------------------------------------------------------------------------------------
------------------------------------------------------------------------------------------------

-- Sql question 1
with high_salary as (
    select department_id,
           salary,
           difference_previous_slary
    from (
             select E.department_id                                                 as department_id,
                    E.salary                                                        as salary,
                    row_number() over (order by E.department_id,E.salary desc)      as RN,
                    lag(salary)                                                     as previous_salary,
                    salary - LAG(salary) OVER (ORDER BY department_id,salary desc ) AS difference_previous_slary
             from Employees E
             order by E.department_id, E.salary desc
         )
    where RN = 1
)

select D.name, E.first_name, E.last_name, E.salary, H.difference_previous_slary
from Employees E
         inner join Departments D
                    on E.department_id = D.id
         inner join high_salary H
                    on E.salary = H.salary and E.department_id = H.department_id
;
-- Note: if 2 employees work in the same department and earn the same salary,
--       with this logic implement in the query, one of them will be choose randomaly.
------------------------------------------------------------------------------------------------
------------------------------------------------------------------------------------------------

-- Sql question 2

with Employees_Num as (
    select count(distinct ID) as Total_Employees
    from Employees E
),

     Employees_Num_3_years as (
                           select count(distinct ID) as Total_Employees_3_years
    from (
             select ID,
                    DATEDIFF(year, sysdate, hire_date) AS DateDiff
             from Employees E
         )
    where DateDiff > 3
         )

select (Total_Employees_3_years / Total_Employees) * 100 as employees_precent
from Employees_Num_3_years Y
    cross join Employees_Num N
where 1 = 1
;
