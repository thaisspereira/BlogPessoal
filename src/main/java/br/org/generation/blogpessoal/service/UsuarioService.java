package br.org.generation.blogpessoal.service;

import java.nio.charset.Charset;
import java.util.Optional;

import org.apache.commons.codec.binary.Base64;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import br.org.generation.blogpessoal.model.Usuario;
import br.org.generation.blogpessoal.model.UsuarioLogar;
import br.org.generation.blogpessoal.repository.UsuarioRepository;

@Service
public class UsuarioService {
	
	@Autowired
    private UsuarioRepository usuarioRepository;

    public Optional<Usuario> cadastrarUsuario(Usuario usuario) {

        if (usuarioRepository.findByUsuario(usuario.getUsuario()).isPresent())
            return Optional.empty();

        usuario.setSenha(criptografarSenha(usuario.getSenha()));

        return Optional.of(usuarioRepository.save(usuario));

    }
    public Optional<Usuario> atualizarUsuario(Usuario usuario) {

        if (usuarioRepository.findById(usuario.getId()).isPresent()) {

            Optional<Usuario> buscaUsuario = usuarioRepository.findByUsuario(usuario.getUsuario());

            if (buscaUsuario.isPresent()) {
                if (buscaUsuario.get().getId() != usuario.getId())
                    return Optional.empty();
            }

            usuario.setSenha(criptografarSenha(usuario.getSenha()));

            return Optional.of(usuarioRepository.save(usuario));
        }

        return Optional.empty();
    }

    public Optional<UsuarioLogar> autenticarUsuario(Optional<UsuarioLogar> usuarioLogar) {

        Optional<Usuario> usuario = usuarioRepository.findByUsuario(usuarioLogar.get().getUsuario());

        if (usuario.isPresent()) {
            if (compararSenhas(usuarioLogar.get().getSenha(), usuario.get().getSenha())) {

                String token = gerarBasicToken(usuarioLogar.get().getUsuario(), usuarioLogar.get().getSenha());

                usuarioLogar.get().setId(usuario.get().getId());
                usuarioLogar.get().setNome(usuario.get().getNome());
                usuarioLogar.get().setSenha(usuario.get().getSenha());
                usuarioLogar.get().setToken(token);

                return usuarioLogar;

            }
        }

        return Optional.empty();

    }

    private String criptografarSenha(String senha) {

        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();

        return encoder.encode(senha);

    }

    private boolean compararSenhas(String senhaDigitada, String senhaBanco) {

        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();

        return encoder.matches(senhaDigitada, senhaBanco);

    }

    private String gerarBasicToken(String email, String password) {

        String tokenBase = email + ":" + password;
        byte[] tokenBase64 = Base64.encodeBase64(tokenBase.getBytes(Charset.forName("US-ASCII")));
        return "Basic " + new String(tokenBase64);

    }

}

