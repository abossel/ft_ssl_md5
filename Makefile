SRCS	= ft_ssl.c libft.c dynar.c md5.c sha256.c

OBJS	= ${SRCS:.c=.o}

NAME	= ft_ssl

CC		= gcc

CFLAGS	= -Wall -Wextra -Werror

LFLAGS	=

RM		= rm -f

all:	${NAME}

.c.o:
	${CC} ${CFLAGS} -c $< -o ${<:.c=.o}

${NAME}:	${OBJS}
	${CC} -o ${NAME} ${OBJS} ${LFLAGS}

clean:
	${RM} ${OBJS}

fclean: clean
	${RM} ${NAME}

re:	fclean all

.PHONY:	all clean fclean re
