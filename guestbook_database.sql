-- Table: public."user"

-- DROP TABLE public."user";

CREATE TABLE public."user"
(
    id integer NOT NULL DEFAULT nextval('user_id_seq'::regclass),
    email text COLLATE pg_catalog."default" NOT NULL,
    username text COLLATE pg_catalog."default" NOT NULL,
    password text COLLATE pg_catalog."default" NOT NULL,
    email_confirmed boolean NOT NULL,
    reset_token text COLLATE pg_catalog."default",
    CONSTRAINT user_pkey PRIMARY KEY (id, email, username),
    CONSTRAINT "unique" UNIQUE (id, username)
,
    CONSTRAINT unique_id UNIQUE (id)
,
    CONSTRAINT unique_username UNIQUE (username)

)

TABLESPACE pg_default;

ALTER TABLE public."user"
    OWNER to postgres;

-- Trigger: delete_user_comms

-- DROP TRIGGER delete_user_comms ON public."user";

CREATE TRIGGER delete_user_comms
    AFTER DELETE
    ON public."user"
    FOR EACH ROW
    EXECUTE PROCEDURE public.delete_comments();
	
	
	
-- Table: public.comments

-- DROP TABLE public.comments;

CREATE TABLE public.comments
(
    id integer NOT NULL DEFAULT nextval('comments_id_seq'::regclass),
    name text COLLATE pg_catalog."default",
    comment text COLLATE pg_catalog."default",
    CONSTRAINT comments_pkey PRIMARY KEY (id)
)

TABLESPACE pg_default;

ALTER TABLE public.comments
    OWNER to postgres;

-- Index: fki_delete user comments

-- DROP INDEX public."fki_delete user comments";

CREATE INDEX "fki_delete user comments"
    ON public.comments USING btree
    (name COLLATE pg_catalog."default")
    TABLESPACE pg_default;
	
	

-- FUNCTION: public.delete_comments()

-- DROP FUNCTION public.delete_comments();

CREATE FUNCTION public.delete_comments()
    RETURNS trigger
    LANGUAGE 'plpgsql'
    COST 100
    VOLATILE NOT LEAKPROOF
AS $BODY$begin
delete from public.comments where name=old.username;
return null;
end;$BODY$;

ALTER FUNCTION public.delete_comments()
    OWNER TO postgres;